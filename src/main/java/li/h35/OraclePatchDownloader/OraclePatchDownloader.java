package li.h35.OraclePatchDownloader;

/*
 * Copyright (c) 2024 H35 GmbH
 * Copyright (c) 2024 Jens Schmidt
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.htmlunit.BrowserVersion;
import org.htmlunit.DefaultCredentialsProvider;
import org.htmlunit.ElementNotFoundException;
import org.htmlunit.Page;
import org.htmlunit.SgmlPage;
import org.htmlunit.TextPage;
import org.htmlunit.UnexpectedPage;
import org.htmlunit.WebClient;
import org.htmlunit.WebRequest;
import org.htmlunit.WebResponse;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlRadioButtonInput;
import org.htmlunit.html.HtmlTable;
import org.htmlunit.html.HtmlTableCell;
import org.htmlunit.html.HtmlTableRow;
import org.htmlunit.util.NameValuePair;
import org.htmlunit.util.WebConnectionWrapper;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

public class OraclePatchDownloader {
	//-----------------------------------------------------------------
	// enums and inner classes
	//-----------------------------------------------------------------

	private static enum SecondFAType { Default, TOTP, SMS, None }

	private static class DownloadFile {
		private final String name;

		@SuppressWarnings("unused")
		private final long size;

		private final String url;

		private final String sha256;

		private DownloadFile(String name, long size, String url, String sha256) {
			this.name   = name;
			this.size   = size;
			this.url    = url;
			this.sha256 = sha256;
		}
	}

	//-----------------------------------------------------------------
	// constants
	//-----------------------------------------------------------------

	// user-agent to use.  When masquerading as wget, MOS accepts
	// basic authentication for patch searches and downloads.
	private final static String USER_AGENT = "Wget/1.21.3";

	// short-hands for XPathConstants
	private final static QName XPC_STRING  = XPathConstants.STRING;
	private final static QName XPC_NODE    = XPathConstants.NODE;
	private final static QName XPC_NODESET = XPathConstants.NODESET;

	// regex that matches a line in a patch file.  The first
	// subgroup provides the patch number.
	private final static String  PATCH_FILE_LINE_REGEX   = "^p?(\\d{8,10}).*$";
	private final static Pattern PATCH_FILE_LINE_PATTERN = Pattern.compile(PATCH_FILE_LINE_REGEX);

	// XPath expression to search for errors
	private final static String RESULT_ERROR_XPE  = "/results/error";

	// XPath expression to search for downloadable files
	private final static String DOWNLOAD_FILE_XPE = "/results/patch/files/file";

	//-----------------------------------------------------------------
	// "global" variables
	//-----------------------------------------------------------------

	private static boolean debugMode = false;
	private static boolean quietMode = false;
	private static File directory = null;
	private static ArrayList<String> patchList = new ArrayList<>();
	private static HashMap<String, List<String>> queryMap = new HashMap<>();
	private static ArrayList<Pattern> patternList = new ArrayList<>();
	private static String user = null;
	// do not use a character array here plus some "burn after
	// reading" processing, even if that is the general convention
	// for handling passwords.  The security gain does not seem to
	// justify the effort required to do so.
	private static String password = null;
	private static SecondFAType secondFAType = SecondFAType.Default;
	private static File tempdir = null;

	//-----------------------------------------------------------------
	// string formatting
	//-----------------------------------------------------------------

	// like String.format, but protects against format errors.
	// This is to avoid exception handling resulting in exceptions,
	// which is disgusting.
	private static String format(String format, Object... args) {
		try {
			return String.format(format, args);
		}
		catch (IllegalFormatException e) {
			System.err.println("Cannot process format \"" + format + "\"");
			e.printStackTrace(System.err);
			StringBuffer result = new StringBuffer();
			result.append(format);
			result.append("[");
			for (int i = 0; i < args.length; i++) {
				result.append(args[i]);
				if (i < args.length - 1)
					result.append(", ");
			}
			result.append("]");
			return result.toString();
		}
	}

	//-----------------------------------------------------------------
	// errors, warnings, progress
	//-----------------------------------------------------------------

	// Try to handle errors in this tool as follows:
	//
	// - Avoid using System.exit(), as that may circumvent cleanup;
	// - Call method usage() in method main();
	// - Call method error() in method download() and methods
	//   called from that;
	// - Throw a RuntimeException otherwise.
	//
	// To report warnings and progress use methods warn() and
	// progress(), respectively.

	private static class ExitException extends Exception {
		private final static long serialVersionUID = 1L;

		public final int exitval;

		public ExitException(int exitval) {
			this.exitval = exitval;
		}
	}

	private static void error(String format, Exception e, Page p, Object... args)
		throws ExitException {
		System.err.println(format(format, args));
		if (e != null)
			e.printStackTrace(System.err);
		if (p != null && debugMode)
			dumpInternal(p, true);
		throw new ExitException(1);
	}

	private static void error(String format, Page p, Object... args)
		throws ExitException {
		error(format, (Exception)null, p, args);
	}

	@SuppressWarnings("unused")
	private static void error(String format, Exception e, Object... args)
		throws ExitException {
		error(format, e, (Page)null, args);
	}

	private static void error(String format, Object... args)
		throws ExitException {
		error(format, (Exception)null, (Page)null, args);
	}

	private static void warn(String format, Exception e, Page p, Object... args) {
		System.err.println(format(format, args));
		if (e != null)
			e.printStackTrace(System.err);
		if (p != null && debugMode)
			dumpInternal(p, true);
	}

	private static void warn(String format, Page p, Object... args) {
		warn(format, (Exception)null, p, args);
	}

	private static void warn(String format, Exception e, Object... args) {
		warn(format, e, (Page)null, args);
	}

	private static void warn(String format, Object... args) {
		warn(format, (Exception)null, (Page)null, args);
	}

	private static void warn() {
		System.err.println();
	}

	private static void progress(String format, Object... args) {
		if (! quietMode)
			System.err.println(format(format, args));
	}

	private static void progress() {
		if (! quietMode)
			System.err.println();
	}

	private static void result(String format, Object... args) {
		if (! quietMode)
			System.out.println(format(format, args));
	}

	//-----------------------------------------------------------------
	// logging and dumping
	//-----------------------------------------------------------------

	private static void rrlog(PrintWriter rrLogWriter, WebRequest request) {
		try {
			// dump request.  Use some dummy HTTP version, since the
			// real one does not seem to be easily available.
			long ctm = System.currentTimeMillis();
			rrLogWriter.println(format("%s %s HTTP/0.0 (%tF %tT)",
																 request.getHttpMethod(),
																 request.getUrl(),
																 ctm, ctm));
			for (Map.Entry<String, String> header :
						 new TreeMap<>(request.getAdditionalHeaders()).entrySet())
				rrLogWriter.println(format("%s=%s", header.getKey(), header.getValue()));
			List<NameValuePair> parameters = request.getRequestParameters();
			if (parameters.size() > 0)
				rrLogWriter.println();
			for (NameValuePair parameter : parameters)
				rrLogWriter.println(parameter);
			rrLogWriter.println();
			rrLogWriter.flush();
		}
		catch (Exception e) {
			warn("Cannot write to request-response log file", e);
		}
	}

	private static void rrlog(PrintWriter rrLogWriter, WebResponse response) {
		try {
			// dump response
			long ctm = System.currentTimeMillis();
			rrLogWriter.println(format("HTTP/0.0 %03d %s (%tF %tT)",
																 response.getStatusCode(),
																 response.getStatusMessage(),
																 ctm, ctm));
			for (NameValuePair header : response.getResponseHeaders())
				rrLogWriter.println(header);
			rrLogWriter.println();
			rrLogWriter.println(format("<content of length %d>",
																 response.getContentLength()));
			rrLogWriter.println();
			rrLogWriter.flush();
		}
		catch (Exception e) {
			warn("Cannot write to request-response log file", e);
		}
	}

	private static void dumpInternal(Page page, boolean onerror) {
		try {
			// determine some human-readable page Id
			String pageId =
				(page instanceof HtmlPage) ?
				((HtmlPage)page).getTitleText() :
				page.getUrl().toString();

			// ensure page Id consists entirely of sane characters
			pageId = pageId.toLowerCase()
				.replaceFirst("\\A[^0-9a-z]+", "")
				.replaceFirst("[^0-9a-z]+\\z", "")
				.replaceAll("[^0-9a-z]+", "-");
			if (pageId.length() == 0)
				pageId = String.format("%08x", page.hashCode());

			// determine dump file name
			String dfn =
				String.format("%s-%016x-%s.%s",
											onerror ? "error" : "dump",
											System.currentTimeMillis(), pageId,
											(page instanceof SgmlPage) ? "xml" : "txt");

			try (FileWriter dfw = new FileWriter(new File(directory, dfn))) {
				if (page instanceof SgmlPage)
					dfw.write(((SgmlPage)page).asXml());
				else if (page instanceof TextPage)
					dfw.write(((TextPage)page).getContent());
				else
					dfw.write(page.toString());
			}
			catch (IOException e) {
				warn("Cannot write dump file \"%s\"", e, dfn);
			}
		}
		catch (Exception e) {
			warn("Cannot write page dump file", e);
		}
	}

	private static void dump(Page page) {
		if (debugMode)
			dumpInternal(page, false);
	}

	//-----------------------------------------------------------------
	// user input
	//-----------------------------------------------------------------

	private static String readThing(boolean password, String prompt, Object... args) {
		Console console = System.console();
		if (console != null) {
			if (password) {
				return new String(console.readPassword(prompt, args));
			}
			else {
				return console.readLine(prompt, args);
			}
		}
		else {
			try {
				if (password) {
					// use System.out here, since the password prompt is
					// also written to System.out
					System.out.println("No console available, reading password with echo from STDIN");
				}
				System.out.print(String.format(prompt, args));
				String result =
					(new BufferedReader(new InputStreamReader(System.in))).readLine();
				if (result == null)
					throw new RuntimeException("Cannot read line from STDIN (EOF)");
				return result;
			}
			catch (IOException e) {
				throw new RuntimeException("Cannot read line from STDIN", e);
			}
		}
	}

	private static String readLine(String prompt, Object... args) {
		return readThing(false, prompt, args);
	}

	private static String readPassword(String prompt, Object... args) {
		return readThing(true, prompt, args);
	}

	//-----------------------------------------------------------------
	// auxilliary methods
	//-----------------------------------------------------------------

	// returns the query URL from the specified patch and the
	// user-specified query map
	private static String getQueryUrl(String patch) {
		StringBuffer url =
			new StringBuffer("https://updates.oracle.com/Orion/Services/search");
		url.append("?bug=").append(patch);
		for (Map.Entry<String, List<String>> query : queryMap.entrySet()) {
			url.append("&").append(query.getKey()).append("=");
			url.append(String.join(",", query.getValue()));
		}
		return url.toString();
	}

	private static boolean isPatchDownloaded(String patch) {
		String[] list = directory.list(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.startsWith("p" + patch) && name.endsWith(".zip");
			}
		});
		return list.length > 0;
	}

	//-----------------------------------------------------------------
	// download
	//-----------------------------------------------------------------

	public static void download() throws Exception {
		List<DownloadFile> downloads = new ArrayList<>();
		List<String> searchErrorList = new ArrayList<>();

		// force english content since we identify login progress by
		// (localized) content
		BrowserVersion.BrowserVersionBuilder browserVersionBuilder =
			new BrowserVersion.BrowserVersionBuilder(BrowserVersion.FIREFOX);
		browserVersionBuilder
			.setUserAgent(USER_AGENT)
			.setBrowserLanguage("en-US")
			.setAcceptLanguageHeader("en-US");

		// determine request-response log file
		File rrLogFile;
		if (debugMode)
			rrLogFile = new File(directory,
													 String.format("%s-%016x.%s",
																				 "reqresp",
																				 System.currentTimeMillis(),
																				 "log"));
		else
			rrLogFile = null;

		try (WebClient webClient = new WebClient(browserVersionBuilder.build());
				 PrintWriter rrLogWriter =
					 debugMode ?
					 new PrintWriter(new FileWriter(rrLogFile)) :
					 null) {
			webClient.getOptions().setJavaScriptEnabled(true);
			webClient.getOptions().setTempFileDirectory(tempdir);

			// unconditionally use basic authentication.  See issue
			// #12.
			DefaultCredentialsProvider creds = new DefaultCredentialsProvider();
			creds.addCredentials(user, password.toCharArray());
			webClient.setCredentialsProvider(creds);

			// set a custom web connection wrapper to be able to log
			// requests and their responses
			webClient.setWebConnection(new WebConnectionWrapper(webClient) {
				@Override
				public WebResponse getResponse(WebRequest request) throws IOException {
					if (debugMode)
						rrlog(rrLogWriter, request);
					WebResponse response = super.getResponse(request);
					if (debugMode)
						rrlog(rrLogWriter, response);
					return response;
				}
			});

			Logger.getLogger("org.htmlunit").setLevel(Level.SEVERE);
			// some OAM villains try to set invalid cookies - silence
			// the corresponding org.apache.http.client warnings
			Logger.getLogger("org.apache.http.client.protocol.ResponseProcessCookies")
				.setLevel(Level.SEVERE);

			// prepare for parsing and processing XML
			DocumentBuilder xmlparser =
				DocumentBuilderFactory.newInstance().newDocumentBuilder();
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression errorXPE  = xpath.compile(RESULT_ERROR_XPE);
			XPathExpression dlfileXPE = xpath.compile(DOWNLOAD_FILE_XPE);

			// maintain both abstract and HTML pages in sync.  Why?
			//
			// Because ultimately we want to fetch XML content provided
			// by MOS, which is protected by Oracle's login sqeuence.
			// Accordingly, we have to handle a sequence of HTML pages
			// of varying length for the login, all pages instances of
			// HtmlPage, which is concluded by the final XML content as
			// an instance of a TextPage.
			//
			// Therefore we handle the separate steps of the login
			// sequence with the following pattern:
			//
			//   if (page instanceof HtmlPage &&
			//       (hpage = (HtmlPage)page) != null &&
			//       <tests on hpage>) {
			//     [...]
			//     page = <operate on hpage>;
			//     dump(page);
			//   }
			Page page = null;
			HtmlPage hpage = null;

			for (String patch : patchList) {
				if (isPatchDownloaded(patch))
					continue;
				page = webClient.getPage(getQueryUrl(patch));
				dump(page);

				// A short overview on how HtmlUnit methods react when
				// some element is absent:
				//
				// DomElement.getAttribute:     returns ATTRIBUTE_NOT_DEFINED
				// DomNode.getByXPath:          returns empty list
				// DomNode.getFirstByXPath:     returns null
				// DomNode.querySelector:       returns null
				// HtmlPage.getElementById:     returns null
				// HtmlPage.getElementsById:    returns empty list
				// HtmlPage.getFormByName:      throws ENFE
				// HtmlPage.getHtmlElementById: throws ENFE
				// HtmlForm.getInputByName:     throws ENFE
				// HtmlForm.getInputByValue:    throws ENFE

				if (page instanceof HtmlPage &&
						(hpage = (HtmlPage)page) != null &&
						hpage.getTitleText().equals("Oracle Login - Single Sign On")) {
					progress("Processing login page...");
					try {
						HtmlForm form = hpage.getFormByName("LoginForm");
						form.getInputByName("ssousername").type(user);
						form.getInputByName("password").type(password);
						page = hpage.getHtmlElementById("signin_button").click();
						dump(page);
					}
					catch (ElementNotFoundException e) {
						error("Cannot process login page", e, page);
					}
				}

				if (page instanceof HtmlPage &&
						(hpage = (HtmlPage)page) != null &&
						hpage.getTitleText().equals("Login - Oracle Access Management 11g") &&
						hpage.getElementById("loginForm") != null &&
						hpage.getElementById("loginForm").asNormalizedText()
								 .indexOf("Please choose your preferred method") >= 0) {
					progress("Processing 2FA selection page...");
					try {
						HtmlForm form = hpage.getFormByName("loginForm");
						if (secondFAType.equals(SecondFAType.Default)) {
							// determine the default 2FA method.  To avoid an
							// exception when one of the methods is not
							// available, protect the calls to ENFE-throwing
							// method getInputByValue() by equivalent calls
							// to method getFirstByXPath().
							try {
								if ((form.getFirstByXPath(".//input[@type='radio'][@value='Totp']") != null) &&
										((HtmlRadioButtonInput)form.getInputByValue("Totp")).isChecked()) {
									secondFAType = SecondFAType.TOTP;
								}
								else if ((form.getFirstByXPath(".//input[@type='radio'][@value='Sms']") != null) &&
												 ((HtmlRadioButtonInput)form.getInputByValue("Sms")).isChecked()) {
									secondFAType = SecondFAType.SMS;
								}
								else {
									error("Cannot process 2FA selection page", page);
								}
							}
							catch (ClassCastException e) {
								error("Cannot process 2FA selection page", e, page);
							}
						}
						else if (secondFAType.equals(SecondFAType.TOTP)) {
							form.getInputByValue("Totp").click();
						}
						else if (secondFAType.equals(SecondFAType.SMS)) {
							form.getInputByValue("Sms").click();
						}
						else {
							error("Cannot process 2FA selection page", page);
						}
						page = form.getInputByValue("OK").click();
						dump(page);
					}
					catch (ElementNotFoundException e) {
						error("Cannot process 2FA selection page", e, page);
					}
				}

				if (page instanceof HtmlPage &&
						(hpage = (HtmlPage)page) != null &&
						hpage.getTitleText().equals("Login - Oracle Access Management 11g") &&
						hpage.querySelector("label[for='username']") != null &&
						hpage.querySelector("label[for='username']").asNormalizedText()
								 .equals("Enter One Time Pin:")) {
					progress("Processing 2FA entry page...");
					String prompt;
					if (secondFAType.equals(SecondFAType.TOTP)) {
						prompt = "TOTP: ";
					}
					else if (secondFAType.equals(SecondFAType.SMS)) {
						prompt = "SMS PIN: ";
					}
					else {
						prompt = null;
						error("Cannot process 2FA entry page", page);
					}
					String otp = readLine(prompt);
					try {
						HtmlForm form = hpage.getFormByName("loginForm");
						form.getInputByName("passcode").type(otp);
						page = form.getInputByValue("Login").click();
						dump(page);
					}
					catch (ElementNotFoundException e) {
						error("Cannot process 2FA entry page", e, page);
					}
				}

				// ensure we ended up on the patch search result XML
				String content;
				if (page instanceof TextPage &&
						(content = ((TextPage)page).getContent()) != null &&
						(content.startsWith("<results>") ||
						 content.startsWith("<results "))) {
					progress("Processing search results for patch \"%s\"...", patch);

					Document result =
						xmlparser.parse(new InputSource(new StringReader(content)));

					// check for search errors.  For now only warn about
					// them, but throw an error after we have completed (or
					// not) downloading any remaining patches.
					Node error;
					if ((error = (Node)errorXPE.evaluate(result, XPC_NODE)) != null) {
						warn("Cannot process search error \"%s\"",
						     page, error.getTextContent().trim().replaceAll("\\s+", " "));
						searchErrorList.add(patch);
					}

					NodeList dlfiles = (NodeList)dlfileXPE.evaluate(result, XPC_NODESET);
					for (int i = 0; i < dlfiles.getLength(); i++) {
						Node dlfile = dlfiles.item(i);

						// extract parts of the download file node
						String name = (String)xpath.evaluate("./name/text()", dlfile, XPC_STRING);
						String size = (String)xpath.evaluate("./size/text()", dlfile, XPC_STRING);
						String host = (String)xpath.evaluate("./download_url/@host", dlfile, XPC_STRING);
						String path = (String)xpath.evaluate("./download_url/text()", dlfile, XPC_STRING);
						String sha256 =
							(String)xpath.evaluate("./digest[@type='SHA-256']/text()", dlfile, XPC_STRING);

						// verify them at least to some extent
						if (name == null || name.length() == 0)
							error("Cannot process download file name \"%s\"", page, name);
						if (size == null || ! size.matches("\\d+"))
							error("Cannot process download file size \"%s\"", page, size);
						if (host == null || ! host.startsWith("https://"))
							error("Cannot process download file host \"%s\"", page, host);
						if (path == null || path.length() == 0)
							error("Cannot process download file path \"%s\"", page, path);
						if (sha256 == null || ! sha256.matches("\\p{XDigit}{64}"))
							error("Cannot process download file sha256 \"%s\"", page, sha256);

						// create a new download file and check its name
						// against the user-specified patterns
						DownloadFile dlf =
						  new DownloadFile(name, Long.parseLong(size), host + path, sha256 );
						if (patternList.size() > 0) {
							for (Pattern pattern : patternList) {
								if (pattern.matcher(name).matches()) {
									downloads.add(dlf);
									break;
								}
							}
						}
						else
							downloads.add(dlf);
					}

					xmlparser.reset();
				}
				else if (page instanceof HtmlPage &&
								 (hpage = (HtmlPage)page) != null)
					error("Cannot process unexpected page \"%s\" - login failed?",
								hpage, hpage.getTitleText());
				else
					error("Cannot process unexpected page - login failed?", page);
			}

			// give some feedback if there is nothing to do
			if (downloads.size() == 0)
				warn("No new patches selected for download");

			for (DownloadFile dlf : downloads) {
				File outputFile = new File(directory, dlf.name);
				if (outputFile.exists() && outputFile.length() > 0)
					continue;

				Page p = webClient.getPage(dlf.url);
				if (p.isHtmlPage())
					error("Cannot process unexpected page \"%s\"",
								p, ((HtmlPage)p).getTitleText());
				UnexpectedPage unexpectedPage = (UnexpectedPage) p;
				try (InputStream inputStream = unexpectedPage.getInputStream();
						 FileOutputStream outputStream = new FileOutputStream(outputFile)) {
					// Save the stream to the file
					byte[] buffer = new byte[8192];
					int bytesRead;
					while ((bytesRead = inputStream.read(buffer)) != -1) {
						outputStream.write(buffer, 0, bytesRead);
					}
					progress("File \"%s\" downloaded successfully.", dlf.name);
				}
			}

			// dump checksums if there were any downloads and if we run
			// non-silent
			if (downloads.size() > 0 && ! quietMode) {
				progress();
				progress("SHA-256 checksums as provided by MOS:");
				for (DownloadFile dlf : downloads)
					result("%s  %s", dlf.sha256, dlf.name);
			}

			// dump information on search errors and error out if there
			// were any
			if (searchErrorList.size() > 0) {
				warn();
				warn("Search errors occurred for the following patches:");
				for (String patch : searchErrorList)
					warn("  %s", patch);
				error("Cannot process previous search errors");
			}
		}
	}

	//-----------------------------------------------------------------
	// main method and friends
	//-----------------------------------------------------------------

	private static void help() {
		System.out.println("Usage:");
		System.out.println(" -h : --help        help text");
		System.out.println(" -D : --debug       debug mode");
		System.out.println(" -Q : --quiet       quiet mode");
		System.out.println(" -d : --directory   output folder, default user home");
		System.out.println(" -x : --patches     list of patches");
		System.out.println("                    (e.g. \"p12345678\", \"12345678\")");
		System.out.println(" -f : --patchfile   file containing list of patches, one patch per line");
		System.out.println("                    (e.g. \"p12345678\", \"12345678\", \"# comment\")");
		System.out.println(" -q : --query |     list of platforms, releases, or languages");
		System.out.println(" -t : --platforms   (e.g. \"226P\" for Linux x86-64, \"600000000063735R\"");
		System.out.println("                    for OPatch 12.2.0.1.2 or \"4L\" for German (D))");
		System.out.println("                    (e.g. \"226P\" for Linux x86-64 or \"4L\" for German (D))");
		System.out.println(" -r : --regex       regex for file filter, multiple possible");
		System.out.println("                    (e.g. \".*1900.*\")");
		System.out.println(" -u : --user        email/userid");
		System.out.println(" -p : --password    password (\"env:ENV_VAR\" to use password from env)");
		System.out.println(" -T : --temp        temporary directory");
	}

	private static void usage(String format, Object... args) {
		System.err.println(format(format, args));
		help();
		System.exit(2);
	}

	public static void main(String[] args) {

		int c;
		ArrayList<LongOpt> longopts = new ArrayList<>();
		longopts.add( new LongOpt("help",      LongOpt.NO_ARGUMENT,       null, 'h') );
		longopts.add( new LongOpt("debug",     LongOpt.NO_ARGUMENT,       null, 'D') );
		longopts.add( new LongOpt("quiet",     LongOpt.NO_ARGUMENT,       null, 'Q') );
		longopts.add( new LongOpt("directory", LongOpt.REQUIRED_ARGUMENT, null, 'd') );
		longopts.add( new LongOpt("patches",   LongOpt.REQUIRED_ARGUMENT, null, 'x') );
		longopts.add( new LongOpt("patchfile", LongOpt.REQUIRED_ARGUMENT, null, 'f') );
		longopts.add( new LongOpt("query",     LongOpt.REQUIRED_ARGUMENT, null, 'q') );
		longopts.add( new LongOpt("platforms", LongOpt.REQUIRED_ARGUMENT, null, 't') );
		longopts.add( new LongOpt("regex",     LongOpt.REQUIRED_ARGUMENT, null, 'r') );
		longopts.add( new LongOpt("user",      LongOpt.REQUIRED_ARGUMENT, null, 'u') );
		longopts.add( new LongOpt("password",  LongOpt.REQUIRED_ARGUMENT, null, 'p') );
		longopts.add( new LongOpt("2fatype",   LongOpt.REQUIRED_ARGUMENT, null, '2') );
		longopts.add( new LongOpt("temp",      LongOpt.REQUIRED_ARGUMENT, null, 'T') );

		Getopt g = new Getopt("OraclePatchDownoader", args,
													"hDQd:x:f:q:t:r:u:p:2:T:",
													longopts.toArray(new LongOpt[longopts.size()]));
		g.setOpterr(false); // do our own error handling
		directory = new File(System.getProperty("user.home"));
		tempdir = new File(System.getProperty("java.io.tmpdir"));
		boolean tempdirDelete = false;

		List<String> queryList = new ArrayList<>();
		while ((c = g.getopt()) != -1) {
			String arg = g.getOptarg();

			switch (c) {
			case 'h':
				help();
				System.exit(0);
				break;

			case 'D':
				debugMode = true;
				break;

			case 'Q':
				quietMode = true;
				break;

			case 'd':
				directory = new File(arg);

				if (!directory.exists()) {
					directory.mkdirs();
				}
				break;

			case 'x':
				for (String patch : arg.split("[,;]+")) {
					if (patch.length() > 0) {
						patchList.add(patch);
					}
				}
				break;

			case 'f':
				File fp = new File(arg);
				if (fp.exists()) {
					String line;
					try (BufferedReader br = new BufferedReader(new FileReader(fp))) {
						while ((line = br.readLine()) != null) {
							Matcher matcher = PATCH_FILE_LINE_PATTERN.matcher(line.trim());
							if (matcher.matches()) {
								String px = matcher.group(1);
								patchList.add(px);
							}
						}
					}
					catch (IOException e) {
						usage("Invalid file \"%s\" specified (%s)", arg, e.getMessage());
					}
				}
				else {
					usage("Missing file \"%s\" specified", arg);
				}
				break;

			case 'q':
			case 't':
				for (String query : arg.split("[,;]+")) {
					if (query.length() > 0) {
						queryList.add(query);
					}
				}
				break;

			case 'r':
				try {
					patternList.add(Pattern.compile(arg));
				}
				catch (PatternSyntaxException e) {
					usage("Invalid regexp \"%s\" specified", arg);
				}
				break;

			case 'u':
				user = arg;
				break;

			case 'p':
				password = arg;
				if (password.startsWith("env:")) {
					// resolve environment variable reference
					String envVar = password.substring(4);
					password = System.getenv(envVar);
					if (password == null)
						usage("Missing environment variable \"%s\" specified", envVar);
				}
				break;

			case '2':
				try {
					secondFAType = SecondFAType.valueOf(arg);
				}
				catch (IllegalArgumentException e) {
					usage("Invalid 2FA type \"%s\"", arg);
				}
				break;

			case 'T':
				tempdir = new File(arg);
				if (!tempdir.exists()) {
					tempdir.mkdirs();
					tempdirDelete = true;
				}
				break;

			default:
				usage("Invalid or incomplete option specified");
				break;
			}
		}

		if (patchList.size() == 0)
			usage("No patches specified");
		if (queryList.size() == 0)
			usage("No platforms or query specified");

		// verify the user-specified query items and build the query
		// map from them
		for (String query : queryList) {
			if (! query.matches("\\d+[LPR]"))
				usage("Invalid platforms or query \"%s\"specified", query);

			// determine query id and term
			int qlmo = query.length() - 1;            // query-lenght-minus-one
			String qid = query.substring(0, qlmo);
			String qt  = null;
			switch (query.charAt(qlmo)) {
			case 'L': qt = "language"; break;
			case 'P': qt = "platform"; break;
			case 'R': qt = "release";  break;
			}

			// associate query id to query term in the map
			List<String> qids;
			if (queryMap.containsKey(qt))
				qids = queryMap.get(qt);
			else
				queryMap.put(qt, qids = new ArrayList<>());
			qids.add(qid);
		}

		if (user == null)
			user = readLine("MOS Username: ");
		if (password == null)
			password = readPassword("MOS Password: ");

		int exitRc = 0;
		try {
			download();
		}
		catch (ExitException e) {
			// do not dump the stack trace here - method error()
			// already has seen to that
			exitRc = e.exitval;
		}
		catch (Exception e) {
			System.err.println("Cannot download patches");
			e.printStackTrace(System.err);
			exitRc = 1;
		}
		finally {
			if (tempdirDelete) {
				for (File f : tempdir.listFiles()) {
					f.delete();
				}
				tempdir.delete();
			}
		}

		System.exit(exitRc);

	}
}
