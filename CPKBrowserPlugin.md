#CPK Browser Plugin

# Introduction #

CPK Browser Plugin provides a scriptable object for Web browsers. JavaScript code can call this object with CPK functions.

Here are some examples:




```
<html>
<head>
<title>Web Browser Crypto Plugin</title>
<script>
	window.onload = function() {
		var cpk = document.getElementById("plugin").cpk;
		
	}
</script>
</head>
<body>
	<h1>CPK Cryptography Plugin</h1>
	<hr>

	<embed name="plugin" type="application/x-cpk" id="plugin"></embed>
	<br>

	<script>
		var cpk = document.getElementById("plugin").cpk;
		document.write("User's identity: ");
		document.write(cpk.identity);
		document.write("<br>");
		
		document.write("Sign message \"hello\" with your key: ");
		var signature = cpk.sign("hello");
		document.write(signature);
		document.write("<br>");

		document.write("Verify: ");
		document.write(cpk.verify("hello", signature, cpk.identity));
		document.write("<br>");

		document.write("Encrypt message \"hello\" to \"alice@cpksecurity.com\": ");
		var ciphertext = cpk.encrypt("hello", "alice@cpksecurity.com");
		document.write(ciphertext);
		document.write("<br>");
		document.write("Decrypt result: ");
		var plaintext = cpk.decrypt(ciphertext);
		document.write(plaintext);
		document.write("<br>");
	</script> 


</body>
</html>
```

CPK Plugin currently supports Firefox/Chromium/Opera in Linux.

You can validate the output of this plugin with our CPK command line tool. For example, you can copy the
base64 encoded signature and run the command

```
echo hello | head -c 5 | cpk -verify MDQCGFJoKtF10UJQSeGVtHgjl/FJdk9kTjb1wQIYXVSNVdvqGc021hD0M1kh4na9RaS6DVR4 -signer alice@cpksecurity.com
```