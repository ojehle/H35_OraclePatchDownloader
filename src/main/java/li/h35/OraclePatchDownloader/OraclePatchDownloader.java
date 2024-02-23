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
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.htmlunit.BrowserVersion;
import org.htmlunit.Page;
import org.htmlunit.UnexpectedPage;
import org.htmlunit.WebClient;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlTable;
import org.htmlunit.html.HtmlTableCell;
import org.htmlunit.html.HtmlTableRow;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

public class OraclePatchDownloader {
	private static String patchRegex = "^([p]{0,1})([0-9]{8}).*$";
	private static Pattern patchPattern = Pattern.compile(patchRegex);
	private static String regex = "(?:^|\\?|&)patch_file=(.*?)(?:&|$)";
	private static Pattern pattern = Pattern.compile(regex);
	private static File directory = null;
	private static String user = null;
	private static String password = null;
	private static ArrayList<String> plattform = new ArrayList<String>();
	private static boolean checkPatchList = false;
	private static ArrayList<Pattern> patchRegexp = new ArrayList<Pattern>();
	private static ArrayList<String> patchList = new ArrayList<String>();

	public static String getPatchFile(String url) {
		Matcher matcher = pattern.matcher(url);
		if (matcher.find()) {
			return matcher.group(1);
		}
		return "";
	}

	public String getDownloadUrl(String patch, String plattform) {
		return "https://updates.oracle.com/Orion/SimpleSearch/process_form?search_type=patch&patch_number=" + patch
				+ "&plat_lang=" + plattform;
	}

	public boolean isPatchDownloaded(String patch) {
		String[] list = directory.list(new FilenameFilter() {
			public boolean accept(File dir, String name) {
				return name.startsWith("p" + patch) && name.endsWith(".zip");
			}
		});
		return list.length > 0;
	}

	public OraclePatchDownloader() {
		ArrayList<String> downloads = new ArrayList<String>();
		boolean loggedIn = false;

		WebClient webClient = new WebClient(BrowserVersion.FIREFOX);		
		webClient.getOptions().setJavaScriptEnabled(true);
		Logger.getLogger("org.htmlunit").setLevel(Level.SEVERE);
		HtmlPage page = null;
		try {
			webClient.getOptions().setTempFileDirectory(new File(directory, "tmp"));

			for (String patch : patchList) {
				if (isPatchDownloaded(patch))
					continue;
				for (String p : plattform) {
					page = webClient.getPage(getDownloadUrl(patch, p));
					if (!loggedIn) {
						for (HtmlForm f : page.getForms()) {
							if (f.getNameAttribute().equalsIgnoreCase("LoginForm")) {
								HtmlForm form = page.getFormByName("LoginForm");
								form.getInputByName("ssousername").type(user);
								form.getInputByName("password").type(password);
								HtmlInput in = page.getHtmlElementById("signin_button");
								page = in.click(); // works fine
								page = webClient.getPage(getDownloadUrl(patch, p));
							}
						}
					}

					for (DomElement e : page.getElementsByTagName("table")) {
						if (e instanceof HtmlTable) {
							for (HtmlTableRow r : ((HtmlTable) e).getRows()) {
								for (HtmlTableCell c : r.getCells()) {
									for (org.htmlunit.html.HtmlElement el : c.getHtmlElementDescendants()) {
										String u = el.getAttribute("href");
										if (u.startsWith("https") && u.contains(".zip")) {
											if (patchRegexp.size() > 0) {
												for (Pattern pattern : patchRegexp) {
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
			webClient.close();
			int exitRc = 0;
			if (checkPatchList) {
				for (String patch : patchList) {

					if (isPatchDownloaded(patch))
						continue;
					exitRc = 1;
					System.out.println("Patch " + patch + " missing");
				}
			}
			System.exit(exitRc);
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	private static void help() {
		System.out.println("usage:");
		System.out.println(" -h : --help        help text");
		System.out.println(" -d : --directory   output folder, default user home");
		System.out.println(" -x : --patch       comma separated list of patches or multiple possible");
		System.out.println(" -f : --patchfile   patch list as file, one patch per line , # is ignored");
		System.out.println(
				" -t : --plattform   Plattform Code 226P (Linux X86_64) or Langauge Code 4L, comma separated  ");
		System.out.println(" -r : --regex       regex for file filter, multiple possible");
		System.out.println(" -u : --user        email/userid");
		System.out.println(" -p : --password    password");
		System.out.println(" -c : --check       check patchlist after download");
	}

	public static void main(String[] args) {

		int c;
		LongOpt[] longopts = new LongOpt[9];
		longopts[0] = new LongOpt("help", LongOpt.NO_ARGUMENT, null, 'h');
		longopts[1] = new LongOpt("check", LongOpt.NO_ARGUMENT, null, 'c');
		longopts[2] = new LongOpt("directory", LongOpt.REQUIRED_ARGUMENT, null, 'd');
		longopts[3] = new LongOpt("patches", LongOpt.REQUIRED_ARGUMENT, null, 'x');
		longopts[4] = new LongOpt("plattform", LongOpt.REQUIRED_ARGUMENT, null, 't');
		longopts[5] = new LongOpt("regex", LongOpt.REQUIRED_ARGUMENT, null, 'r');
		longopts[6] = new LongOpt("user", LongOpt.REQUIRED_ARGUMENT, null, 'u');
		longopts[7] = new LongOpt("password", LongOpt.REQUIRED_ARGUMENT, null, 'p');
		longopts[8] = new LongOpt("patchfile", LongOpt.REQUIRED_ARGUMENT, null, 'f');

		Getopt g = new Getopt("OraclePatchDownoader", args, "hcd:t:x:r:u:p:f:", longopts);
		directory = new File(System.getProperty("user.home"));

		while ((c = g.getopt()) != -1)
			switch (c) {
			case 'h':
				System.out.println("usage:");
				System.exit(0);
				break;

			case 'd':
				directory = new File(g.getOptarg());

				if (!directory.exists()) {
					if (directory.getParentFile().exists())
						directory.mkdir();
				}
				break;

			//
			case 'r':
				Pattern p = null;
				String s = g.getOptarg();
				try {
					p = Pattern.compile(s);
				} catch (Exception e) {
					System.err.println("cannot parse regexp : " + s);
					e.printStackTrace();
					System.exit(1);
				}
				if (p != null)
					patchRegexp.add(p);
				break;

			case 'x':
				String[] pl = g.getOptarg().split(",");
				for (String patch : pl) {
					patchList.add(patch);
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
				break;

			case 't':
				String pa = g.getOptarg();
				pa = pa.replace(";", ",");
				String[] pal = pa.split(",");
				for (String px : pal) {
					plattform.add(px);
				}

				break;
			case 'p':
				password = g.getOptarg();
				break;
			case 'u':
				user = g.getOptarg();
				break;

			default:
				help();
				System.exit(1);
				break;
			}

		if (user == null || password == null) {
			System.err.println("User or Password missing");
			help();
			System.exit(1);
		}
		if (plattform == null) {
			System.err.println("Plattform missing");
			help();
			System.exit(1);
		}
		if (patchList.size() == 0) {
			System.err.println("no patches specified");
			help();
			System.exit(1);
		}

		new OraclePatchDownloader();

	}
}
