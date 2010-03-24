package org.cpk.crypto.cmdline;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cpk.cms.PKCS7;
import org.cpk.crypto.CPKUtil;
import org.cpk.crypto.KeySerializer;
import org.cpk.crypto.MapAlgMgr;
import org.cpk.crypto.MappingAlgorithmException;
import org.cpk.crypto.pubmatrix.DERPubmatrixSerializer;
import org.cpk.crypto.pubmatrix.PubMatrix;
import org.cpk.crypto.secmatrix.DERSecmatrixSerializer;
import org.cpk.crypto.secmatrix.SecMatrix;

/**
 * 
 * @author zaexage@gmail.com
 */
public class Cmdline {

	private static Logger logger = Logger.getLogger(Cmdline.class);
	/**
	 * @param args
	 * @throws Exception 
	 * @throws URISyntaxException 
	 */
	public static void main(String[] args){
		// TODO Auto-generated method stub
		try{
			PropertyConfigurator.configure(Cmdline.class.getResource("/log4j.properties"));
		}catch(Exception ex){
			System.err.println("log4j not properly configured, ignored...");
		}
		
		try{
			MapAlgMgr.Configure("MapAlg.properties", "OIDMapAlg.properties");
		}catch(Exception ex){
			ex.printStackTrace();
			System.err.println("Not all the configuration files are ready...exit");
			System.err.println("Maybe 'MapAlg.properties' or 'OIDMapAlg.properties' not present?");
			return;
		}	
		
		if( -1 == Security.addProvider(new BouncyCastleProvider())){ //add this provider
			System.err.println("Failed to add BC provider, ignored(maybe already added...)");			
		}
		
		Cmdline cmdline = new Cmdline();
		if(args.length < 1){
			cmdline.Help();
			return;
		}
		String cmd = args[0]; //the sub-command
		String[] subargs = new String[args.length-1];
		System.arraycopy(args, 1, subargs, 0, args.length-1); //create a array without first one
		
		try{
			if ( "gen-secmatrix".equals(cmd)) 		{cmdline.Gen_Secmatrix(subargs);}
			else if ( "gen-pubmatrix".equals(cmd) ) {cmdline.Gen_Pubmatrix(subargs);}
			else if ( "sign".equals(cmd) ) 			{cmdline.Sign(subargs);}
			else if ( "verify".equals(cmd) ) 		{cmdline.Verify(subargs);}
			else if ( "encrypt".equals(cmd) ) 		{cmdline.Encrypt(subargs);}
			else if ( "decrypt".equals(cmd) ) 		{cmdline.Decrypt(subargs);}		
			else if ( "gen-key".equals(cmd) ) 		{cmdline.Gen_Key(subargs);}
			else if ( "help".equals(cmd) ) 			{cmdline.Help();}
			else 									{cmdline.Help();}
		}catch(Exception ex){
			ex.printStackTrace();
		}
		
	}
	
	public void Help(){
		System.out.println("usage: cpk");
		System.out.println("available sub-command:\n gen-secmatrix\n" +
				" gen-pubmatrix\n sign\n verify\n encrypt\n decrypt\n gen-key\n help");
	}
	
	/**
	 * print help info for sub-command
	 * @param options the parsed options specification
	 */
	public void SubHelp(String subcmd, Options options){
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp(subcmd, options);
	}
	
	/////////////////////////////////////////////////////////
	// related to 'gen-secmatrix'
	//
	private class GenSecMatrixNames{
		final private static String OP_EC = "ec";
		final private static String OP_COL = "col";
		final private static String OP_ROW = "row";
		final private static String OP_MAPALG = "map-algo";
		final private static String OP_OUT = "out";
	}
	@SuppressWarnings("static-access")
	public void Gen_Secmatrix(String[] args) throws NoSuchAlgorithmException, SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException, URISyntaxException, IOException  {
		logger.trace("Gen_Secmatrix started");
		Option opEc = OptionBuilder.hasArg().isRequired()
								.withArgName("ec_curve_name")
								.withDescription("specify an named ec curve")
								.withLongOpt(GenSecMatrixNames.OP_EC).create();
		Option opCol = OptionBuilder.hasArg().isRequired()
								.withArgName("col_number")
								.withDescription("the count of column of the secmatrix")
								.withLongOpt(GenSecMatrixNames.OP_COL).create();
		Option opRow = OptionBuilder.hasArg().isRequired()
								.withArgName("row_number")
								.withDescription("the count of row of the secmatrix")
								.withLongOpt(GenSecMatrixNames.OP_ROW).create();
		Option opMapAlg = OptionBuilder.hasArg().isRequired()
								.withArgName("algName")
								.withDescription("the name of the id->key mapping algorithm")
								.withLongOpt(GenSecMatrixNames.OP_MAPALG).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
								.withArgName("matrixFile")
								.withDescription("specify the file name for exported secret matrix")
								.withLongOpt(GenSecMatrixNames.OP_OUT).create();
		Options options = new Options();
		options.addOption(opEc);
		options.addOption(opCol);
		options.addOption(opRow);
		options.addOption(opMapAlg);
		options.addOption(opOut);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Gen_Secmatrix_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: gen-secmatrix: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("gen-secmatrix", options);
		}
	}
	
	/**
	 * the place to do work of gen-secmatrix
	 * @param cmds parsed command-line arguments
	 * @throws URISyntaxException 
	 * @throws ClassNotFoundException 
	 * @throws InvocationTargetException 
	 * @throws IllegalAccessException 
	 * @throws InstantiationException 
	 * @throws NoSuchMethodException 
	 * @throws IllegalArgumentException 
	 * @throws SecurityException 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 */
	private void Gen_Secmatrix_Work(CommandLine cmds) throws NoSuchAlgorithmException, SecurityException, IllegalArgumentException, NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException, ClassNotFoundException, URISyntaxException, IOException  { 
		logger.trace("Gen_Secmatrix_Work");
		String eccurveName = cmds.getOptionValue(GenSecMatrixNames.OP_EC);
		int cCol = Integer.parseInt(cmds.getOptionValue(GenSecMatrixNames.OP_COL));
		int cRow = Integer.parseInt(cmds.getOptionValue(GenSecMatrixNames.OP_ROW));
		String mapAlgName = cmds.getOptionValue(GenSecMatrixNames.OP_MAPALG);
		String outFile = cmds.getOptionValue(GenSecMatrixNames.OP_OUT);
		
		SecMatrix secmatrix = SecMatrix.GenerateNewMatrix(cRow, cCol, eccurveName, mapAlgName, new URI("www.pku.edu.cn"));
		FileOutputStream fos = new FileOutputStream(outFile);
		DERSecmatrixSerializer serial = new DERSecmatrixSerializer(null, fos);
		serial.ExportSecMatrix(secmatrix);
	}
	//
	// related to 'gen-secmatrix' ,,, done
	////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////
	// related to 'gen-pubmatrix'
	//
	private class GenPubMatrixNames{
		final static String OP_IN = "in";
		final static String OP_OUT = "out";
	}
	@SuppressWarnings("static-access")
	public void Gen_Pubmatrix(String[] args) throws NoSuchAlgorithmException, IOException{
		logger.trace("Gen_Pubmatrix started");
		Option opIn = OptionBuilder.hasArg().isRequired()
								.withArgName("secmatrixFile")
								.withDescription("the filename of secret matrix previously exported")
								.withLongOpt(GenPubMatrixNames.OP_IN).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
								.withArgName("pubmatrixFile")
								.withDescription("the name of file where public matrix to be exported")
								.withLongOpt(GenPubMatrixNames.OP_OUT).create();
		Options options = new Options();
		options.addOption(opIn);
		options.addOption(opOut);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Gen_Pubmatrix_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: gen-pubmatrix: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("gen-pubmatrix", options);
		}
	}
	
	private void Gen_Pubmatrix_Work(CommandLine cmds) throws IOException, NoSuchAlgorithmException{
		logger.trace("Gen_Pubmatrix_Work");
		String secmatrixFile = cmds.getOptionValue(GenPubMatrixNames.OP_IN);
		String pubmatrixFile = cmds.getOptionValue(GenPubMatrixNames.OP_OUT);
		
		FileInputStream secin = new FileInputStream(secmatrixFile);
		FileOutputStream pubout = new FileOutputStream(pubmatrixFile);
				
		DERSecmatrixSerializer secSerial = new DERSecmatrixSerializer(secin, null);
		SecMatrix secmatrix = secSerial.GetSecMatrix();
		PubMatrix pubmatrix = secmatrix.DerivePubMatrix();	
		
		DERPubmatrixSerializer pubSerial = new DERPubmatrixSerializer(null, pubout);
		pubSerial.ExportPubMatrix(pubmatrix);
	}
	//
	// related to 'gen-pubmatrix' ,,, done
	////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////
	// related to 'sign'
	//
	private class SignNames{
		final static String OP_KEY = "key";
		final static String OP_IN = "in";
		final static String OP_OUT = "out";
		final static String OP_KEYID = "keyid";
	}
	
	@SuppressWarnings("static-access")
	public void Sign(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, MappingAlgorithmException, SignatureException{
		logger.trace("Sign started");
		Option opKey = OptionBuilder.hasArg().isRequired()
								.withDescription("the file containing the PrivateKey used for signing")
								.withArgName("privateKeyFile")
								.withLongOpt(SignNames.OP_KEY).create();
		Option opIn = OptionBuilder.hasArg().isRequired()
								.withArgName("FileToBeSigned")
								.withDescription("the file to be signed")
								.withLongOpt(SignNames.OP_IN).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
								.withArgName("outputFile")
								.withDescription("where the signature to be output")
								.withLongOpt(SignNames.OP_OUT).create();
		Option opKeyid = OptionBuilder.hasArg().isRequired()
								.withArgName("signerId")
								.withDescription("the signer's id")
								.withLongOpt(SignNames.OP_KEYID).create();
		Options options = new Options();
		options.addOption(opKey);
		options.addOption(opIn);
		options.addOption(opOut);
		options.addOption(opKeyid);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Sign_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: sign: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("sign", options);
		}
	}		
	
	/**
	 * this function will sign the file in memory, and output in PKCS#7 format
	 * [signing in memory is not suitable for stream, trying to fix this]
	 * @param cmds
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws SignatureException 
	 * @throws MappingAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private void Sign_Work(CommandLine cmds) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, MappingAlgorithmException, SignatureException{
		logger.trace("Sign_Work");
		String keyfile = cmds.getOptionValue(SignNames.OP_KEY); //the private key file
		String infile = cmds.getOptionValue(SignNames.OP_IN);
		String outfile = cmds.getOptionValue(SignNames.OP_OUT);
		String keyid = cmds.getOptionValue(SignNames.OP_KEYID);
		
		PrivateKey prikey = KeySerializer.GetPrivateKeyFromFile(keyfile);
		byte[] data = readFileToBytes(infile); //read the to-be-signed data from input file,,, done
		
		CPKUtil util = new CPKUtil((SecMatrix)null, null);
		PKCS7 pkcs7 = new PKCS7(util);
		
		Vector<String> signerIds = new Vector<String>();
		signerIds.add(keyid);
		Vector<PrivateKey> prikeys = new Vector<PrivateKey>();
		prikeys.add(prikey);
		
		byte[] sig = pkcs7.Sign(data, signerIds, prikeys, true);
		
		FileOutputStream fos = new FileOutputStream(outfile);
		fos.write(sig);
		fos.close();
	}
	//
	// related to 'sign' ,,, done
	////////////////////////////////////////////////////////

	/////////////////////////////////////////////////////////
	// related to 'sign'
	//
	private class VerifyNames{
		final static String OP_MATRIX = "matrix";
		final static String OP_SIGNEDFILE = "signed-file";
		final static String OP_SIGFILE = "sig-file";
	}
	
	@SuppressWarnings("static-access")
	public void Verify(String[] args) throws InvalidKeyException, MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, IOException{
		logger.trace("Verify started");
		Option opMatrix = OptionBuilder.hasArg().isRequired()
								.withArgName("public_matrix_filename")
								.withDescription("the filename of public matrix")
								.withLongOpt(VerifyNames.OP_MATRIX).create();
		Option opSignedFile = OptionBuilder.hasArg().isRequired()
								.withArgName("signedFile")
								.withDescription("the file got signed")
								.withLongOpt(VerifyNames.OP_SIGNEDFILE).create();
		Option opSig = OptionBuilder.hasArg().isRequired()
								.withArgName("signatureFile")
								.withDescription("the file containing signature")
								.withLongOpt(VerifyNames.OP_SIGFILE).create();
		Options options = new Options();
		options.addOption(opMatrix);
		options.addOption(opSignedFile);
		options.addOption(opSig);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Verify_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: verify: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("verify", options);
		}
	}

	private void Verify_Work(CommandLine cmds) throws IOException, InvalidKeyException, MappingAlgorithmException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException{
		logger.trace("Verify_Work");
		String pubmatrixFile = cmds.getOptionValue(VerifyNames.OP_MATRIX);
		String signedFile = cmds.getOptionValue(VerifyNames.OP_SIGNEDFILE);
		String sigFile = cmds.getOptionValue(VerifyNames.OP_SIGFILE);
		
		FileInputStream fis = new FileInputStream(pubmatrixFile);
		DERPubmatrixSerializer pubSerial = new DERPubmatrixSerializer(fis, null);
		PubMatrix pubmatrix = pubSerial.GetPubMatrix();
		
		byte[] signature = readFileToBytes(sigFile);
		byte[] detachedData = readFileToBytes(signedFile);
		
		CPKUtil util = new CPKUtil(null, pubmatrix);
		PKCS7 pkcs7 = new PKCS7(util);
		boolean result = pkcs7.Verify(signature, detachedData);
		
		System.out.println(String.format("the result for verifying signature %s against %s: %s", 
				sigFile, signedFile, (result ? "Valid" : "Invalid")));
	}
	//
	// related to 'sign' ,,, done
	////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////
	// related to 'gen-key'
	//
	private class Gen_KeyNames{
		final static String OP_ID = "id";
		final static String OP_SECMATRIX = "in";
		final static String OP_OUT = "out";
	}
	
	@SuppressWarnings("static-access")
	public void Gen_Key(String[] args) throws InvalidKeySpecException, MappingAlgorithmException, IOException{
		logger.trace("Gen_Key started");
		Option opId = OptionBuilder.hasArg().isRequired()
							.withArgName("ID")
							.withDescription("the id used to generate the PrivateKey")
							.withLongOpt(Gen_KeyNames.OP_ID).create();
		Option opSecmatrix = OptionBuilder.hasArg().isRequired()
							.withArgName("secmatrix")
							.withDescription("the file containing the secret matrix")
							.withLongOpt(Gen_KeyNames.OP_SECMATRIX).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
							.withArgName("privateKeyOutFile")
							.withDescription("the file where PrivateKey to be exported")
							.withLongOpt(Gen_KeyNames.OP_OUT).create();
		Options options = new Options();
		options.addOption(opId);
		options.addOption(opSecmatrix);
		options.addOption(opOut);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Gen_Key_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: verify: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("verify", options);
		}
	}
	
	private void Gen_Key_Work(CommandLine cmds) throws IOException, InvalidKeySpecException, MappingAlgorithmException{
		logger.trace("Gen_Key_Work");
		String id = cmds.getOptionValue(Gen_KeyNames.OP_ID);
		String secmatFile = cmds.getOptionValue(Gen_KeyNames.OP_SECMATRIX);
		String outFile = cmds.getOptionValue(Gen_KeyNames.OP_OUT);
		
		FileInputStream fis = new FileInputStream(secmatFile);
		DERSecmatrixSerializer secSerial = new DERSecmatrixSerializer(fis, null);
		SecMatrix secmatrix = secSerial.GetSecMatrix();
		
		PrivateKey prikey = secmatrix.GeneratePrivateKey(id);
		KeySerializer.PutPrivateKeyToFile(prikey, outFile);
	}
	
	//
	// related to 'gen-key' ,,, done
	////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////
	// related to 'encrypt'
	//
	private class EncryptNames{
		final static String OP_INFILE = "in";
		final static String OP_KEYFILE = "key";
		final static String OP_OUTFILE = "out";
		final static String OP_RECVER = "recipient";
		final static String OP_PUBMATRIX = "pubmatrix";
	}
	
	@SuppressWarnings("static-access")
	public void Encrypt(String[] args) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException{
		logger.trace("Encrypt started");
		Option opIn = OptionBuilder.hasArg().isRequired()
							.withArgName("FileToEncrypt")
							.withDescription("the file according to which cipher text will be generated")
							.withLongOpt(EncryptNames.OP_INFILE).create();
		Option opKey = OptionBuilder.hasArg().isRequired()
							.withArgName("PrivateKey")
							.withDescription("the file containing private key")
							.withLongOpt(EncryptNames.OP_KEYFILE).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
							.withArgName("outputFile")
							.withDescription("the file where cipher text to be output")
							.withLongOpt(EncryptNames.OP_OUTFILE).create();
		Option opRecv = OptionBuilder.hasArg().isRequired()
							.withArgName("recipient")
							.withDescription("the recipient of the cipher text")
							.withLongOpt(EncryptNames.OP_RECVER).create();
		Option opPubmat = OptionBuilder.hasArg().isRequired()
							.withArgName("pubmatrix")
							.withDescription("the file containing public matrix")
							.withLongOpt(EncryptNames.OP_PUBMATRIX).create();
		Options options = new Options();
		options.addOption(opIn);
		options.addOption(opKey);
		options.addOption(opOut);
		options.addOption(opRecv);
		options.addOption(opPubmat);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Encrypt_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: encrypt: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("encrypt", options);
		}
	}
	
	public void Encrypt_Work(CommandLine cmds) throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		logger.trace("Encrypt_Work");
		String inFile = cmds.getOptionValue(EncryptNames.OP_INFILE);
		String outFile = cmds.getOptionValue(EncryptNames.OP_OUTFILE);
		String keyFile = cmds.getOptionValue(EncryptNames.OP_KEYFILE);
		String recipient = cmds.getOptionValue(EncryptNames.OP_RECVER);
		String pubmatrixFile = cmds.getOptionValue(EncryptNames.OP_PUBMATRIX);
		
		FileInputStream pubIn = new FileInputStream(pubmatrixFile);
		DERPubmatrixSerializer pubSerial = new DERPubmatrixSerializer(pubIn, null);
		PrivateKey prikey = KeySerializer.GetPrivateKeyFromFile(keyFile);
		FileInputStream inputfis = new FileInputStream(inFile);
		FileOutputStream outputfos = new FileOutputStream(outFile);
				
		CPKUtil util = new CPKUtil(null, pubSerial);
		util.Encrypt(inputfis, outputfos, prikey, recipient);
		
		pubIn.close();
		inputfis.close();
		outputfos.close();
	}
	//
	// related to 'encrypt' ,,, done
	////////////////////////////////////////////////////////
	
	/////////////////////////////////////////////////////////
	// related to 'decrypt'
	//
	private class DecryptNames{
		final static String OP_KEYFILE = "key";
		final static String OP_CIPHER = "in";
		final static String OP_SENDER = "sender";	
		final static String OP_PUBMATRIX = "pubmatrix";
		final static String OP_OUTFILE = "out";
	}
	
	@SuppressWarnings("static-access")
	public void Decrypt(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException{
		logger.trace("Decrypt started");
		Option opKey = OptionBuilder.hasArg().isRequired()
							.withArgName("PrivateKey")
							.withDescription("the file containing private key")
							.withLongOpt(DecryptNames.OP_KEYFILE).create();
		Option opCipher = OptionBuilder.hasArg().isRequired()
							.withArgName("cipherFile")
							.withDescription("the file containing cipher text")
							.withLongOpt(DecryptNames.OP_CIPHER).create();
		Option sender = OptionBuilder.hasArg().isRequired()
							.withArgName("senderId")
							.withDescription("the sender's ID")
							.withLongOpt(DecryptNames.OP_SENDER).create();
		Option opPubmat = OptionBuilder.hasArg().isRequired()
							.withArgName("pubmatrix")
							.withDescription("the file containing public matrix")
							.withLongOpt(DecryptNames.OP_PUBMATRIX).create();
		Option opOut = OptionBuilder.hasArg().isRequired()
							.withArgName("outputFile")
							.withDescription("the file where cipher text to be output")
							.withLongOpt(DecryptNames.OP_OUTFILE).create();
		Options options = new Options();
		options.addOption(opKey);
		options.addOption(opCipher);
		options.addOption(sender);
		options.addOption(opPubmat);
		options.addOption(opOut);
		
		CommandLineParser parser = new GnuParser();
		try{
			CommandLine line = parser.parse(options, args);
			Decrypt_Work(line);
		}catch(ParseException ex){
			System.err.println("cpk: decrypt: parse commands failure:"+ex.getMessage());
			logger.error(ex.getMessage());
			SubHelp("decrypt", options);
		}
	}
	
	private void Decrypt_Work(CommandLine cmds) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException{
		logger.trace("Decrypt_Work");
		String keyFile = cmds.getOptionValue(DecryptNames.OP_KEYFILE);
		String cipherFile = cmds.getOptionValue(DecryptNames.OP_CIPHER);
		String senderId = cmds.getOptionValue(DecryptNames.OP_SENDER);
		String pubmatrixFile = cmds.getOptionValue(DecryptNames.OP_PUBMATRIX);
		String outFile = cmds.getOptionValue(DecryptNames.OP_OUTFILE);
		
		FileInputStream pubIn = new FileInputStream(pubmatrixFile);
		DERPubmatrixSerializer pubSerial = new DERPubmatrixSerializer(pubIn, null);
		PrivateKey prikey = KeySerializer.GetPrivateKeyFromFile(keyFile);
		FileInputStream inputfis = new FileInputStream(cipherFile);
		FileOutputStream outputfos = new FileOutputStream(outFile);
				
		CPKUtil util = new CPKUtil(null, pubSerial);
		util.Decrypt(inputfis, outputfos, prikey, senderId);
		
		outputfos.close();
		inputfis.close();
		pubIn.close();
	}
	
	//
	// related to 'decrypt' ,,, done
	////////////////////////////////////////////////////////
	
	private byte[] readFileToBytes(String filename) throws IOException{
		FileInputStream fis = new FileInputStream(filename);
		byte[] buf = new byte[4096];
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while(true){
			int len = fis.read(buf);
			if ( -1 == len ){
				fis.close();
				break;
			}
			baos.write(buf, 0, len);
		}
		return baos.toByteArray();
	}
	
}
