package li.h35.OraclePatchDownloader;

/*
 * Copyright (c) 2024 H35 GmbH
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
import java.util.ArrayList;
import java.util.IllegalFormatException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.htmlunit.BrowserVersion;
import org.htmlunit.ElementNotFoundException;
import org.htmlunit.Page;
import org.htmlunit.SgmlPage;
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
	private static enum SecondFAType { Default, TOTP, SMS, None }

	//-----------------------------------------------------------------
	// constants
	//-----------------------------------------------------------------

	// regex that finds a patch file name in a patch download URL.
	// The first subgroup provides the patch file name.
	private final static String  PATCH_URL_FILE_REGEX   = "(?:^|\\?|&)patch_file=(.*?)(?:&|$)";
	private final static Pattern PATCH_URL_FILE_PATTERN = Pattern.compile(PATCH_URL_FILE_REGEX);

	// regex that matches a line in a patch file.  The first
	// subgroup provides the patch number.
	private final static String  PATCH_FILE_LINE_REGEX   = "^p?(\\d{8,10}).*$";
	private final static Pattern PATCH_FILE_LINE_PATTERN = Pattern.compile(PATCH_FILE_LINE_REGEX);

	//-----------------------------------------------------------------
	// "global" variables
	//-----------------------------------------------------------------

	private static boolean debugMode = false;
	private static boolean quietMode = false;
	private static File directory = null;
	private static ArrayList<String> patchList = new ArrayList<String>();
	private static ArrayList<String> platformList = new ArrayList<String>();
	private static ArrayList<Pattern> patternList = new ArrayList<Pattern>();
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

	private static void error(String format, Exception e, Object... args)
		throws ExitException {
		error(format, e, (Page)null, args);
	}

	private static void error(String format, Object... args)
		throws ExitException {
		error(format, (Exception)null, (Page)null, args);
	}

	private static void warn(String format, Exception e, Object... args) {
		System.err.println(format(format, args));
		if (e != null)
			e.printStackTrace(System.err);
	}

	private static void warn(String format, Object... args) {
		warn(format, (Exception)null, args);
	}

	private static void progress(String format, Object... args) {
		if (! quietMode)
			System.err.println(format(format, args));
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

	private static String getPatchFile(String url) {
		Matcher matcher = PATCH_URL_FILE_PATTERN.matcher(url);
		if (matcher.find()) {
			return matcher.group(1);
		}
		return "";
	}

	private static String getDownloadUrl(String patch, String platform) {
		return "https://updates.oracle.com/Orion/SimpleSearch/process_form?search_type=patch&patch_number=" + patch
				+ "&plat_lang=" + platform;
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
		ArrayList<String> downloads = new ArrayList<String>();

		// force english content since we identify login progress by
		// (localized) content
		BrowserVersion.BrowserVersionBuilder browserVersionBuilder =
			new BrowserVersion.BrowserVersionBuilder(BrowserVersion.FIREFOX);
		browserVersionBuilder.setBrowserLanguage("en-US");
		browserVersionBuilder.setAcceptLanguageHeader("en-US");

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

			HtmlPage page = null;

			for (String patch : patchList) {
				if (isPatchDownloaded(patch))
					continue;
				for (String platform : platformList) {
					page = webClient.getPage(getDownloadUrl(patch, platform));
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

					if (page.getTitleText().equals("Oracle Login - Single Sign On")) {
						progress("Processing login page...");
						try {
							HtmlForm form = page.getFormByName("LoginForm");
							form.getInputByName("ssousername").type(user);
							form.getInputByName("password").type(password);
							page = page.getHtmlElementById("signin_button").click();
							dump(page);
						}
						catch (ElementNotFoundException e) {
							error("Cannot process login page", e, page);
						}
					}

					if (page.getTitleText().equals("Login - Oracle Access Management 11g") &&
							page.getElementById("loginForm") != null &&
							page.getElementById("loginForm").asNormalizedText()
									.indexOf("Please choose your preferred method") >= 0) {
						progress("Processing 2FA selection page...");
						try {
							HtmlForm form = page.getFormByName("loginForm");
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

					if (page.getTitleText().equals("Login - Oracle Access Management 11g") &&
							page.querySelector("label[for='username']") != null &&
							page.querySelector("label[for='username']").asNormalizedText()
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
							HtmlForm form = page.getFormByName("loginForm");
							form.getInputByName("passcode").type(otp);
							page = form.getInputByValue("Login").click();
							dump(page);
						}
						catch (ElementNotFoundException e) {
							error("Cannot process 2FA entry page", e, page);
						}
					}

					// ensure we ended up on the patch search results,
					// otherwise bail out
					if (page.getTitleText().equals("Search Results"))
						progress("Processing search results (\"%s\", \"%s\")...",
										 patch, platform);
					else
						error("Cannot process unexpected page \"%s\" - login failed?",
									page, page.getTitleText());

					// loop over all download links, which are identified
					// by having an image with title "Download Now"
					for (DomElement link :
								 page.<DomElement>getByXPath("//a[img[@title='Download Now']]")) {
						String u = link.getAttribute("href");
						if (u.startsWith("https") && u.contains(".zip")) {
							if (patternList.size() > 0) {
								for (Pattern pattern : patternList) {
									if (pattern.matcher(u).matches()) {
										downloads.add(u);
										break;
									}
								}
							} else {
								downloads.add(u);
							}
						}
					}
				}
			}

			// give some feedback if there is nothing to do
			if (downloads.size() == 0)
				warn("No new patches selected for download");

			for (String u : downloads) {
				String filename = getPatchFile(u);
				File outputFile = new File(directory, filename);
				if (outputFile.exists() && outputFile.length() > 0)
					continue;

				Page p = webClient.getPage(u);
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
					progress("File \"%s\" downloaded successfully.", filename);
				}
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
		System.out.println(" -q : --quiet       quiet mode");
		System.out.println(" -d : --directory   output folder, default user home");
		System.out.println(" -x : --patches     list of patches");
		System.out.println("                    (e.g. \"p12345678\", \"12345678\")");
		System.out.println(" -f : --patchfile   file containing list of patches, one patch per line");
		System.out.println("                    (e.g. \"p12345678\", \"12345678\", \"# comment\")");
		System.out.println(" -t : --platforms   list of platforms or languages");
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
		longopts.add( new LongOpt("quiet",     LongOpt.NO_ARGUMENT,       null, 'q') );
		longopts.add( new LongOpt("directory", LongOpt.REQUIRED_ARGUMENT, null, 'd') );
		longopts.add( new LongOpt("patches",   LongOpt.REQUIRED_ARGUMENT, null, 'x') );
		longopts.add( new LongOpt("patchfile", LongOpt.REQUIRED_ARGUMENT, null, 'f') );
		longopts.add( new LongOpt("platforms", LongOpt.REQUIRED_ARGUMENT, null, 't') );
		longopts.add( new LongOpt("regex",     LongOpt.REQUIRED_ARGUMENT, null, 'r') );
		longopts.add( new LongOpt("user",      LongOpt.REQUIRED_ARGUMENT, null, 'u') );
		longopts.add( new LongOpt("password",  LongOpt.REQUIRED_ARGUMENT, null, 'p') );
		longopts.add( new LongOpt("2fatype",   LongOpt.REQUIRED_ARGUMENT, null, '2') );
		longopts.add( new LongOpt("temp",      LongOpt.REQUIRED_ARGUMENT, null, 'T') );

		Getopt g = new Getopt("OraclePatchDownoader", args,
													"hDqd:x:f:t:r:u:p:2:T:",
													longopts.toArray(new LongOpt[longopts.size()]));
		g.setOpterr(false); // do our own error handling
		directory = new File(System.getProperty("user.home"));
		tempdir = new File(System.getProperty("java.io.tmpdir"));
		boolean tempdirDelete = false;

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

			case 'q':
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

			case 't':
				for (String platform : arg.split("[,;]+")) {
					if (platform.length() > 0) {
						platformList.add(platform);
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
		if (platformList.size() == 0)
			usage("No platforms specified");

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
