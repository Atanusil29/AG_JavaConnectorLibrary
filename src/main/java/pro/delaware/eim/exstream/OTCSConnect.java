package pro.delaware.eim.exstream;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.ByteArrayBody;
import org.apache.http.entity.mime.content.StringBody;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * 
 * @author Bart
 *
 */
class OTCSConnect {

	private String contentServerURL = null;
	private String authTicket = null;

	private String contentServerUsername = null;
	private String contentServerPassword = null;

	private String webReportResult = null;

	private String documentID = null;

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		String URL = "https://xecm-demo.dcsc.be/OTCS/cs.exe";
		String Username = "AGLTest";
		String Password = "AglAgl2@";
		
		String WebReportName = "WR_TestForExstream";
		String[] parameters = new String[]{"TradeID"};
		String[] parValues = new String[]{"55"};
		
		String WebReportValue = "DocID";
		
		String Filepath = "C://CSFetch";

		String NodeID = "1816777";
		String ext = "pdf";
		
		String DocFound = null;
		String DocName = null;
		String ObjectID = null;

		//DISPATCH PROCESS
		OTCSConnect OTCS_Object = new OTCSConnect();
		
		OTCS_Object.CS_SetCredentials(URL, Username, Password);
		OTCS_Object.CS_GetOTCSTicket();
		OTCS_Object.CS_GetWebReport(WebReportName, parameters, parValues);
		
		DocFound = OTCS_Object.ParseWebReportParam("DocFound");
		DocName = OTCS_Object.ParseWebReportParam("DocName");
		ObjectID = OTCS_Object.ParseWebReportParam("ObjectID");
		
		OTCS_Object.CS_GetDocument(Filepath, DocName, ext, NodeID); 
		
//		TEMPLATE GENERATION PROCESS
//		String filepath = "C:/CSFetch";
//		String fileName = "Doge";
//		String parentID= "1832783";
////		String ext = "pdf";
//		String ReturnID = "";
//		
//		OTCSConnect OTCS_Object = new OTCSConnect();
//		
//		OTCS_Object.CS_SetCredentials(URL, Username, Password);
//		OTCS_Object.CS_GetOTCSTicket();
//		ReturnID = OTCS_Object.CS_WriteDocument(filepath, fileName, ext, parentID);
//		
//		System.out.println("Returned ID : " + ReturnID);
//		
//		if (ReturnID == "null" ){
//			System.out.println("Writing to CS failed");
//		} else {
//			System.out.println("Writing to CS succeeded");
//		}
		
		// Password encryption decryption
//	    final String secretKey = ".";
//	     
//	    OTCSConnect OTCS_Object = new OTCSConnect();
//	    
//	    String originalString = "Test";
	    
	    
//	    String encryptedString = OTCS_Object.encrypt(originalString, secretKey) ;
//	    String decryptedString = OTCS_Object.decrypt("TawvuFjb+35Z4SJHnLzwvQ==") ;
//	     
//	    System.out.println(originalString);
//	    System.out.println(decryptedString);
	}
/**
 * Beschrijving
 * 
 * @param URL - parameter descr
 * @param Username
 * @param Password
 * @return
 */
	
	//////////////////////////////////////////////////////////////////
	// Name: CS_SetCredentials //
	// Function: Sets CS credentials, returns 0 on success //
	// Arguments: - Content Server URL //
	// - Content Server Username //
	// - Content Server Password //
	//////////////////////////////////////////////////////////////////
	String CS_SetCredentials(String URL, String Username, String Password) {
		contentServerURL = URL;
		contentServerUsername = Username;
		contentServerPassword = Password;

		
		if (contentServerURL.isEmpty() || contentServerUsername.isEmpty() || contentServerPassword.isEmpty()) {
			System.out.println("Error : CS_SetCredentials : Not all parameters were set");
			return "Error : CS_SetCredentials : Not all parameters were set";
		} else {
			System.out.println("CS_SetCredentials : CS Credentials succesfully set");
			return "0";
		}
	}

	//////////////////////////////////////////////////////////////////
	// Name: CS_GetOTCSTicket //
	// Function: Gets OTCS ticket using CS credentials //
	// returns 0 on success //
	//////////////////////////////////////////////////////////////////
	
	/**
	 * 
	 * @return
	 */
	String CS_GetOTCSTicket() {

		HttpClient httpclient = HttpClients.createDefault();
		System.out.println("CS_GetOTCSTicket : HTTP Connection instance created");
		HttpPost httppost = new HttpPost(contentServerURL + "/api/v1/auth");
		System.out.println("CS_GetOTCSTicket : Post setup : added url : " + contentServerURL + "/api/v1/auth");

		// Request parameters and other properties.
		List<NameValuePair> params = new ArrayList<NameValuePair>(2);
		params.add(new BasicNameValuePair("username", contentServerUsername));
		params.add(new BasicNameValuePair("password", contentServerPassword));

		try {
			httppost.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		System.out.println("CS_GetOTCSTicket : Post setup : added username : " + contentServerUsername);
		System.out.println("CS_GetOTCSTicket : Post setup : added password");

		// Execute and get the response.
		HttpResponse response;

		try {
			System.out.println("CS_GetOTCSTicket : Posting HTTP...");
			response = httpclient.execute(httppost);

			HttpEntity entity = (HttpEntity) response.getEntity();

			if (entity != null) {

				InputStream instream = ((org.apache.http.HttpEntity) entity).getContent();

				// NB: does not close inputStream, you can use IOUtils.closeQuietly for that
				String theString = IOUtils.toString(instream, "UTF-8");

				// Parse it to JSON for ease of reading
				JSONParser jsonParser = new JSONParser();
				JSONObject jsonObject = (JSONObject) jsonParser.parse(theString);

				try {
					// Try to obtain the OTCS ticket from the returned JSON
					authTicket = (String) jsonObject.get("ticket");
					System.out.println("CS_GetOTCSTicket : Response received");
					if (authTicket.isEmpty()) {
						System.out.println("CS_GetOTCSTicket : Error : OTCS Ticket could not be parsed");
						return "CS_GetOTCSTicket : Error : OTCS Ticket could not be parsed";
					}
					System.out.println("CS_GetOTCSTicket : OTCS Ticket : " + jsonObject.get("ticket"));
				} finally {
					instream.close();
				}
				return "0";
			}
		} catch (IOException e) {
			e.printStackTrace();
			return "CS_GetOTCSTicket : Error : IO Exception";
		} catch (ParseException e) {
			e.printStackTrace();
			return "CS_GetOTCSTicket : Error : ParseException";
		}
		return "CS_GetOTCSTicket : Error : Could not connect, invalid credentials or response";
	}

	//////////////////////////////////////////////////////////////////
	// Name: CS_GetWebReport //
	// Function: Fetches CS Webreport using parameters and webreport //
	// name, returns 0 on success. Web report is written as//
	// JSON in the object variabel CS_WebReport //
	// Arguments: - Web Report Name //
	// - Web Report Parameters [x] //
	// - Web Report Parameter Values [x] //
	//////////////////////////////////////////////////////////////////
	String CS_GetWebReport(String WebReportName, String[] parameters, String[] parValues) {

		String dl = contentServerURL + "/api/v1/webreports/" + WebReportName + "?format=webreport";
		StringBuffer content = new StringBuffer();

		if (parameters.length == parValues.length) {
			for (int i = 0; i < parameters.length; i++) {
				dl = dl + "&" + parameters[i] + "=" + parValues[i];
			}
		} else {
			System.out.println("CS_GetWebReport : Error : Web report amount of parameters and values is not equal");
			return "CS_GetWebReport : Error : Web report amount of parameters and values is not equal";
		}

		// Create the downloadURL
		System.out.println("CS_GetWebReport : added url :" + dl);
		URL url;

		try {

			url = new URL(dl);

			System.out.println("CS_GetWebReport : Posting HTTP...");

			// Open the connection
			HttpURLConnection connect = (HttpURLConnection) url.openConnection();

			// Set the request headers
			connect.setRequestProperty("User-Agent", "Mozilla/5.0");
			connect.setRequestProperty("OTCSticket", authTicket);

			int status = connect.getResponseCode();
			BufferedReader in = null;

			if (status > 299) {
				in = new BufferedReader(new InputStreamReader(connect.getErrorStream()));
				System.out.println("CS_GetWebReport : Retrieving the value did not succeed, url response code: "
						+ connect.getResponseCode());
				return "CS_GetWebReport : Error : Retrieving the value did not succeed, url response code: "
						+ connect.toString();

			} else {
				System.out.println("CS_GetWebReport : Response received");
				in = new BufferedReader(new InputStreamReader(connect.getInputStream()));
			}

			String inputLine;

			while ((inputLine = in.readLine()) != null) {
				content.append(inputLine);
			}

			in.close();
			connect.disconnect();

			System.out.println("CS_GetWebReport : Web Report : " + content.toString());
			webReportResult = content.toString();

			return "0";

		} catch (Exception ex) {
			return "CS_GetWebReport : Exception : Connection did not succeed";
		}
	}

	//////////////////////////////////////////////////////////////////
	// Name: ParseWebReport //
	// Function: Returns parameter from web report fetched //
	// with CS_GetWebReport //
	// Arguments: - Parameter name //
	// Returns -1 if unsuccessful //
	//////////////////////////////////////////////////////////////////
	String ParseWebReportParam(String par) {

		JSONParser jsonParser = new JSONParser();
		JSONObject jsonObject;

		try {
			jsonObject = (JSONObject) jsonParser.parse(webReportResult);
		} catch (ParseException e) {
			e.printStackTrace();
			System.out.println("ParseWebReport : Exception : Error parsing web report");
			return "-1";
		}

		if (jsonObject.get(par).toString().isEmpty()) {
			return "CS_GetWebReportParameter : Error : parameter could not be found";
		} else {
			System.out.println("ParseWebReport : parameter returned : " + par + " : " + jsonObject.get(par));
			return (String) jsonObject.get(par);
		}

	}

	//////////////////////////////////////////////////////////////////
	// Name: CS_GetDocument //
	// Function: Downloads document by nodeID and stores it on //
	// filepath location. Requires object credentials to //
	// be set previously //
	// Arguments: - Filepath where document will be stored //
	// - Name of file to be stored //
	// - File extension (pdf/docx/...) //
	// - Content Server document nodeid //
	//////////////////////////////////////////////////////////////////
	String CS_GetDocument(String filepath, String filename, String ext, String nodeid) {

		// Create the downloadURL
		String dl = contentServerURL + "/api/v1/nodes/" + nodeid + "/content";
		System.out.println("CS_GetDocument : added url :" + dl);

		filepath = filepath + "/" + filename + "." + ext;

		URL url;

		try {
			url = new URL(dl);

			// Open the connection
			HttpURLConnection connect = (HttpURLConnection) url.openConnection();
			System.out.println("CS_GetDocument : Posting HTTP...");

			// Set the request headers
			connect.setRequestProperty("User-Agent", "Mozilla/5.0");
			connect.setRequestProperty("OTCSticket", authTicket);
			connect.setRequestProperty("action", "download");

			// Check whether connection was OK

			if (connect.getResponseCode() == HttpURLConnection.HTTP_OK) {
				System.out.println("CS_GetDocument : Response received");
				try (BufferedInputStream in = new BufferedInputStream(connect.getInputStream());
						FileOutputStream fileOutputStream = new FileOutputStream(filepath)) {

					byte dataBuffer[] = new byte[1024];
					int bytesRead;
					while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
						fileOutputStream.write(dataBuffer, 0, bytesRead);
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
				System.out.println("CS_GetDocument : PDF saved at : " + filepath);
			} else {
				connect.disconnect();

				System.out.println("CS_GetDocument : Retrieving the document did not succeed, url response code: "
						+ connect.getResponseCode());
				return "CS_GetDocument : Retrieving the document did not succeed, url response code: "
						+ connect.getResponseCode();
			}
			connect.disconnect();

			return filepath;

		} catch (Exception ex) {
			return "CS_GetDocument : Connection did not succeed";
		}
	}

	//////////////////////////////////////////////////////////////////
	// Name: CS_WriteDocument //
	// Function: Writes a document on the local system to OTCS //
	// Arguments: - Filepath pointing to folder where document is //
	// stored //
	// - Name of file to be stored //
	// - File extension (pdf/docx/...) //
	// - Content Server parentID //
	// Return: - Returns nodeID of document in CS //
	//////////////////////////////////////////////////////////////////
	String CS_WriteDocument(String filepath, String filename, String ext, String parentid) {

		JSONParser jsonParser = new JSONParser();
		JSONObject jsonObj;

		String dl = contentServerURL + "/api/v1/nodes";

		String jsonBody = "{\"name\": \"" + filename + "22" + "\", \"parent_id\": \"" + parentid
				+ "\", \"type\":\"144\"}";
		filepath = filepath + "/" + filename + "." + ext;
		System.out.println("CS_WriteDocument : File to be uploaded to CS : " + filepath);

		try {
			byte[] bytes = Files.readAllBytes(Paths.get(filepath));

			ByteArrayBody file = new ByteArrayBody(bytes, ContentType.DEFAULT_BINARY, "." + ext);
			StringBody body = new StringBody(jsonBody, ContentType.APPLICATION_JSON);

			HttpClientBuilder builder = HttpClientBuilder.create();
			HttpClient httpClient = builder.build();

			HttpPost httpPost = new HttpPost(dl);
			httpPost.setHeader("OTCSticket", authTicket);
			System.out.println("CS_WriteDocument : POST Parameters" + jsonBody);

			MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
			entityBuilder.setMode(HttpMultipartMode.BROWSER_COMPATIBLE);
			entityBuilder.addPart("file", file);
			entityBuilder.addPart("body", body);

			HttpEntity entity = entityBuilder.build();
			httpPost.setEntity(entity);

			try {
				HttpResponse response = httpClient.execute(httpPost);
				System.out.println("CS_WriteDocument : Posting HTTP...");

				HttpEntity resEntity = response.getEntity();
				if (resEntity != null) {
					String retSrc = EntityUtils.toString(resEntity);
					System.out.println("CS_WriteDocument : Response received");

					try {
						jsonObj = (JSONObject) jsonParser.parse(retSrc);
					} catch (ParseException e) {
						e.printStackTrace();
						System.out.println("CS_WriteDocument : " + retSrc);
						return "CS_WriteDocument : " + retSrc;
					}
					System.out.println("CS_WriteDocument : parameter returned : " + jsonObj.get("id"));
					documentID = String.valueOf(jsonObj.get("id"));
					return documentID;
				}
			} catch (ClientProtocolException e) {
				System.out.println("CS_WriteDocument : HTTP POST connection failed : ClientProtocolException");
				return "CS_WriteDocument : HTTP POST connection failed : IOException";
			} catch (IOException e) {
				System.out.println("CS_WriteDocument : HTTP POST connection failed : ClientProtocolException");
				return "CS_WriteDocument : HTTP POST connection failed : IOException";
			}
		} catch (IOException e1) {
			System.out.println("CS_WriteDocument : Finding or reading failed: IOException");
			return "CS_WriteDocument : Finding or reading document failed : IOException";
		}
		return "-1";
	}

	private static SecretKeySpec secretKey;
	private static byte[] key;

	void setKey(String myKey) {
		MessageDigest sha = null;
		try {
			key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	String decrypt(String strToDecrypt) {
		String secret = "Wnu9VGTh";
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}

}
