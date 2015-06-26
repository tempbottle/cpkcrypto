#CPKTool Java API Description.

# Introduction #

The CPKTool Java API is:

```

class CPKTool {
	
	private native int importParameters(String paramFile);
	private native int setIdentity(String identity);
	private native String getIdentity();
	private native int importSignKey(String keyFile, String password);
	private native int importDecryptKey(String keyFile, String password);
	private native int changeSignPassword(String oldPassword, String newPassword);
	private native int changeDecryptPassword(String oldPassword, String newPassword);
	private native String signText(String toBeSignedMessage, String password);
	private native int verifyText(String signedMessage, String signature, String signer);	
	private native String signFile(String toBeSignedFile, String password);
	private native int verifyFile(String file, String signature, String signer);
	private native String encryptText(String plaintext, String recipient);
	private native String decryptText(String ciphertext, String password);
	private native int envelopeEncryptFile(String inFile, String outFile, String[] recipients);
	private native int developeDecryptFile(String inFile, String outFile, String password);
	private native int formatPreserveSignFile(String inFile, String outFile, String password);
	private native int formatPreserveVerifyFile(String inFile);
	private native int formatPreserveEncryptFile(String inFile, String outFile, String[] recipients);
	private native int formatPreserveDecryptFile(String inFile, String outFile, String password);	

	static {
		System.loadLibrary("cpktool");
	}
}
```

# Example #

At first copy public parameters (public\_params.der) and the demo user alice's private key (alice.pem) to sdcard. We use Java API to import public parameters and private key.
```
		CPKTool cpktool = new CPKTool();
		
		cpktool.importParameters("/sdcard/public_params.der");		
		cpktool.setIdentity("alice@cpksecurity.com");
		cpktool.importSignKey("/sdcard/alice.pem");
		cpktool.importDecryptKey("/sdcard/alice.pem");
```

After initialization we can use CPKTool.java to sign a message and then verify.
```
		String message = "Message to be signed";
		String signature = cpktool.signText(message, password);
		String signer = cpktool.getIdentity();
		int rv = cpktool.verifyText(message, signature, signer);
		if (rv == 0) {
			System.out.println("OK");
		} else {
			System.out.println("Failed");
		}
```

The following example shows how to encrypt a message to myself.
```
		String plaintext = "Message to be encrypted";
		String recipient = cpktool.getIdentity();
		String ciphertext = cpktool.encryptText(plaintext, recipient);
		String result = cpktool.decryptText(ciphertext, password);
```