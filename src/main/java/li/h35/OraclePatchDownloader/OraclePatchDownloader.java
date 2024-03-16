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
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.htmlunit.BrowserVersion;
import org.htmlunit.Page;
import org.htmlunit.UnexpectedPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTable;
import org.htmlunit.html.HtmlTableCell;
import org.htmlunit.html.HtmlTableRow;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

public class OraclePatchDownloader {
	private static enum SecondFAType { None, TOTP, SMS }

	// constants
	private static String patchRegex = "^([p]{0,1})([0-9]{8}).*$";
	private static Pattern patchPattern = Pattern.compile(patchRegex);
	private static String regex = "(?:^|\\?|&)patch_file=(.*?)(?:&|$)";
	private static Pattern pattern = Pattern.compile(regex);

	// "global" variables
	private static File directory = null;
	private static ArrayList<String> patchList = new ArrayList<String>();
	private static ArrayList<String> platformList = new ArrayList<String>();
	private static ArrayList<Pattern> patternList = new ArrayList<Pattern>();
	private static String user = null;
	// do not use a character array here plus some "burn after
	// reading" processing, even if that is the general convention
	// for handling passwords.  We need the password also to ensure
	// its absence in page dumps, which seems to be more importamt.
	private static String password = null;
	private static SecondFAType secondFAType = SecondFAType.None;
	private static File tempdir = null;

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
					System.out.println("No console available, reading password with echo from STDIN");
				}
				System.out.print(String.format(prompt, args));
				String result = (new BufferedReader(new InputStreamReader(System.in))).readLine();
				if (result == null) {
					System.err.println("Cannot read line from STDIN (EOF)");
					System.exit(1);
				}
				return result;
			}
			catch (IOException e) {
				System.err.println("Cannot read line from STDIN");
				e.printStackTrace(System.err);
				System.exit(1);
				return null;
			}
		}
	}

	private static String readLine(String prompt, Object... args) {
		return readThing(false, prompt, args);
	}

	private static String readPassword(String prompt, Object... args) {
		return readThing(true, prompt, args);
	}

	private static String getPatchFile(String url) {
		Matcher matcher = pattern.matcher(url);
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

	public static void download() throws Exception {
		ArrayList<String> downloads = new ArrayList<String>();

		// force english content since we identify login progress by
		// (localized) content
		BrowserVersion.BrowserVersionBuilder browserVersionBuilder =
			new BrowserVersion.BrowserVersionBuilder(BrowserVersion.FIREFOX);
		browserVersionBuilder.setBrowserLanguage("en-US");
		browserVersionBuilder.setAcceptLanguageHeader("en-US");
		WebClient webClient = new WebClient(browserVersionBuilder.build());

		webClient.getOptions().setJavaScriptEnabled(true);
		Logger.getLogger("org.htmlunit").setLevel(Level.SEVERE);
		// some OAM villains try to set invalid cookies - silence the
		// corresponding org.apache.http.client warnings
		Logger.getLogger("org.apache.http.client.protocol.ResponseProcessCookies")
			.setLevel(Level.SEVERE);
		HtmlPage page = null;
		try {
			webClient.getOptions().setTempFileDirectory(tempdir);

			for (String patch : patchList) {
				if (isPatchDownloaded(patch))
					continue;
				for (String platform : platformList) {
					page = webClient.getPage(getDownloadUrl(patch, platform));

					if (page.getTitleText().equals("Oracle Login - Single Sign On")) {
						System.out.println("Processing login page...");
						for (HtmlForm f : page.getForms()) {
							if (f.getNameAttribute().equalsIgnoreCase("LoginForm")) {
								HtmlForm form = page.getFormByName("LoginForm");
								form.getInputByName("ssousername").type(user);
								form.getInputByName("password").type(password);
								HtmlInput in = page.getHtmlElementById("signin_button");
								page = in.click(); // works fine
							}
						}
					}

					if (page.getTitleText().equals("Login - Oracle Access Management 11g") &&
							page.getElementById("loginForm") != null &&
							page.getElementById("loginForm").asNormalizedText()
									.indexOf("Please choose your preferred method") >= 0) {
						System.out.println("Processing 2FA selection page...");
						if (secondFAType.equals(SecondFAType.TOTP) &&
								page.getHtmlElementById("Totp") != null) {
							page.getHtmlElementById("Totp").click();
						}
						else if (secondFAType.equals(SecondFAType.SMS) &&
										 page.getHtmlElementById("Sms") != null) {
							page.getHtmlElementById("Sms").click();
						}
						else {
							System.err.println("Cannot process 2FA selection page");
							System.exit(1);
						}
						page = ((HtmlElement)page.querySelector("input.formButton")).click();
					}

					if (page.getTitleText().equals("Login - Oracle Access Management 11g") &&
							page.querySelector("label[for='username']") != null &&
							page.querySelector("label[for='username']").asNormalizedText()
									.equals("Enter One Time Pin:")) {
						System.out.println("Processing 2FA entry page...");
						String prompt;
						if (secondFAType.equals(SecondFAType.TOTP)) {
							prompt = "TOTP: ";
						}
						else if (secondFAType.equals(SecondFAType.SMS)) {
							prompt = "SMS PIN: ";
						}
						else {
							prompt = null;
							System.err.println("Cannot process 2FA entry page");
							System.exit(1);
						}
						String otp = readLine(prompt);
						page.getHtmlElementById("passcode").type(otp);
						page = ((HtmlElement)page.querySelector("input[type='submit']")).click();
					}

					// ensure we ended up on the patch search results,
					// otherwise bail out
					if (! page.getTitleText().equals("Search Results")) {
						System.err.println("Cannot process page \"" + page.getTitleText() + "\" - login failed?");
						System.exit(1);
					}

					System.out.println("Processing search results...");
					for (DomElement e : page.getElementsByTagName("table")) {
						if (e instanceof HtmlTable) {
							for (HtmlTableRow r : ((HtmlTable) e).getRows()) {
								for (HtmlTableCell c : r.getCells()) {
									for (org.htmlunit.html.HtmlElement el : c.getHtmlElementDescendants()) {
										String u = el.getAttribute("href");
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
						}
					}
				}
			}

			// bail out if no downloads have been selected at all
			if (downloads.size() == 0) {
				System.err.println("Cannot process empty download list");
				System.exit(1);
			}

			for (String u : downloads) {
				String filename = getPatchFile(u);
				File outputFile = new File(directory, filename);
				if (outputFile.exists() && outputFile.length() > 0)
					continue;

				Page p = webClient.getPage(u);
				if (p.isHtmlPage())
					continue;
				UnexpectedPage unexpectedPage = (UnexpectedPage) p;
				InputStream inputStream = unexpectedPage.getInputStream();
				// Save the stream to the file
				FileOutputStream outputStream = new FileOutputStream(outputFile);

				byte[] buffer = new byte[8192];
				int bytesRead;
				while ((bytesRead = inputStream.read(buffer)) != -1) {
					outputStream.write(buffer, 0, bytesRead);
				}
				System.out.println("File " + filename + " downloaded successfully.");
				outputStream.close();
			}
		}
		finally {
			webClient.close();
		}
	}

	private static void help() {
		System.out.println("Usage:");
		System.out.println(" -h : --help        help text");
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
		System.out.println(" -2 : --2fatype     second factor type (one of \"None\", \"TOTP\", \"SMS\")");
		System.out.println(" -T : --temp        temporary directory");
	}

	public static void main(String[] args) {

		int c;
		ArrayList<LongOpt> longopts = new ArrayList<>();
		longopts.add( new LongOpt("help",      LongOpt.NO_ARGUMENT,       null, 'h') );
		longopts.add( new LongOpt("directory", LongOpt.REQUIRED_ARGUMENT, null, 'd') );
		longopts.add( new LongOpt("patches",   LongOpt.REQUIRED_ARGUMENT, null, 'x') );
		longopts.add( new LongOpt("patchfile", LongOpt.REQUIRED_ARGUMENT, null, 'f') );
		longopts.add( new LongOpt("platforms", LongOpt.REQUIRED_ARGUMENT, null, 't') );
		longopts.add( new LongOpt("regex",     LongOpt.REQUIRED_ARGUMENT, null, 'r') );
		longopts.add( new LongOpt("user",      LongOpt.REQUIRED_ARGUMENT, null, 'u') );
		longopts.add( new LongOpt("password",  LongOpt.REQUIRED_ARGUMENT, null, 'p') );
		longopts.add( new LongOpt("2fatype",   LongOpt.REQUIRED_ARGUMENT, null, '2') );
		longopts.add( new LongOpt("temp",      LongOpt.REQUIRED_ARGUMENT, null, 'T') );

		Getopt g = new Getopt("OraclePatchDownoader", args, "hd:x:f:t:r:u:p:2:T:",
													longopts.toArray(new LongOpt[0]));
		directory = new File(System.getProperty("user.home"));
		tempdir = new File(System.getProperty("java.io.tmpdir"));
		boolean tempdirDelete = false;

		while ((c = g.getopt()) != -1)
			switch (c) {
			case 'h':
				help();
				System.exit(0);
				break;

			case 'd':
				directory = new File(g.getOptarg());

				if (!directory.exists()) {
					directory.mkdirs();
				}
				break;

			case 'x':
				for (String patch : g.getOptarg().split("[,;]+")) {
					if (patch.length() > 0) {
						patchList.add(patch);
					}
				}
				break;

			case 'f':
				File fp = new File(g.getOptarg());
				if (fp.exists()) {
					String line;
					try {
						BufferedReader br = new BufferedReader(new FileReader(fp));
						while ((line = br.readLine()) != null) {
							Matcher matcher = patchPattern.matcher(line.trim());
							if (matcher.matches()) {
								String px = matcher.group(2);
								patchList.add(px);
							}
						}
						br.close();
					} catch (Exception e) {
						e.printStackTrace();
						System.exit(1);
					}
				}
				else {
					System.err.println("Cannot find file \"" + fp + "\"");
					System.exit(1);
				}
				break;

			case 't':
				for (String platform : g.getOptarg().split("[,;]+")) {
					if (platform.length() > 0) {
						platformList.add(platform);
					}
				}
				break;

			case 'r':
				try {
					patternList.add(Pattern.compile(g.getOptarg()));
				}
				catch (PatternSyntaxException e) {
					System.err.println("Invalid regexp \"" + g.getOptarg() + "\"");
					e.printStackTrace();
					System.exit(1);
				}
				break;

			case 'u':
				user = g.getOptarg();
				break;

			case 'p':
				password = g.getOptarg();
				if (password.startsWith("env:")) {
					// resolve environment variable reference
					String envVar = password.substring(4);
					password = System.getenv(envVar);
					if (password == null) {
						System.err.println("Invalid environment variable \"" + envVar + "\"");
						help();
						System.exit(1);
					}
				}
				break;

			case '2':
				try {
					secondFAType = SecondFAType.valueOf(g.getOptarg());
				}
				catch (IllegalArgumentException e) {
					System.err.println("Invalid 2FA type \"" + g.getOptarg() + "\"");
					help();
					System.exit(1);
				}
				break;

			case 'T':
				tempdir = new File(g.getOptarg());
				if (!tempdir.exists()) {
					tempdir.mkdirs();
					tempdirDelete = true;
				}
				break;

			default:
				help();
				System.exit(1);
				break;
			}

		if (patchList.size() == 0) {
			System.err.println("No patches specified");
			help();
			System.exit(1);
		}
		if (platformList.size() == 0) {
			System.err.println("No platforms specified");
			help();
			System.exit(1);
		}

		if (user == null) {
			user = readLine("MOS Username: ");
		}
		if (password == null) {
			password = readPassword("MOS Password: ");
		}

		int exitRc = 0;
		try {
			download();
		}
		catch (Exception e) {
			e.printStackTrace();
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
