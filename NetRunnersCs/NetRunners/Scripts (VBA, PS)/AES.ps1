#PowerShell to create an gibberishaes(and openssl) compatible aes string with salt
#Salted__8bitsalt/aesstring
#thanks for .netcode -> http://stackoverflow.com/questions/5452422/openssl-using-only-net-classes
#
# This outputs the same ciphertext as:   echo -n "SomePlainText"|/usr/bin/openssl enc -A -e -aes-256-cbc -a -pass pass:ThePassword
# For decrypt:  echo "[cipherText]"|/usr/bin/openssl base64 -d|/usr/bin/openssl enc -A -d -aes-256-cbc -pass pass:ThePassword

function OpenSSLEncrypt($passphrase, $plainText)
{
	# generate salt
	[byte[]] $key
	[byte[]] $iv;
	[byte[]] $salt = RandomByteArray
	$rng = (new-Object Security.Cryptography.RNGCryptoServiceProvider);
	$res = DeriveKeyAndIV $passphrase $salt
	$key = $res.key
	$iv = $res.iv
	# encrypt bytes
	[byte[]] $encryptedBytes = EncryptStringToBytesAes $plainText $key $iv;
	$encryptedBytes = $encryptedBytes[1..33]   # Increase this if you enter longer plaintext e.g. 128, 256 etc.
	# add salt as first 8 bytes
	[byte[]] $encryptedBytesWithSalt
	$encryptedBytesWithSalt = ([Text.Encoding]::ASCII.GetBytes("Salted__"))
	$encryptedBytesWithSalt += $salt
	$encryptedBytesWithSalt += $encryptedBytes
	# base64 encode
	return [Convert]::ToBase64String($encryptedBytesWithSalt)
}

function DeriveKeyAndIV($passphrase, $salt)
{
	# generate key and iv
	$concatenatedHashes

	[byte[]] $password = [Text.Encoding]::UTF8.GetBytes($passphrase);
	[byte[]] $currentHash =@()
	$md5 = new-object System.Security.Cryptography.MD5CryptoServiceProvider
	[bool] $enoughBytesForKey = $false;
	# See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
	while (!$enoughBytesForKey)
	{
		[byte[]] $preHash = @() 
		$preHash = $currentHash
		$preHash += $password
		$preHash += $salt
		$currentHash = $md5.ComputeHash($preHash);
		$concatenatedHashes += $currentHash;
		if ($concatenatedHashes.Count -ge 48)
		{
			$enoughBytesForKey = $true;
		}
	}

	$key = $concatenatedHashes[0..31]
	$iv = $concatenatedHashes[32..(32+15)]

	$md5.Clear();
	$md5 = $null;
	
	$value = New-Object -TypeName PSObject -Property @{ 
				key = $key
				iv = $iv
		}
	$value
}

function EncryptStringToBytesAes($plainText, $key, $iv)
{
	# Check arguments.
	if ($plainText -eq $null -or $plainText.Length -le 0){
		throw  new-object ArgumentNullException("plainText");}
	if ($key -eq $null -or $key.Length -le 0){
		throw  new-object ArgumentNullException("key");}
	if ($iv -eq $null -or $iv.Length -le 0){
		throw  new-object ArgumentNullException("iv");}

	# Declare the stream used to encrypt to an in memory
	# array of bytes.
	$msEncrypt;

	# Declare the RijndaelManaged object
	# used to encrypt the data.
	$aesAlg = new-Object System.Security.Cryptography.RijndaelManaged

	try
	{
		# Create a RijndaelManaged object
		# with the specified key and IV.
		$aesAlg =  new-object System.Security.Cryptography.RijndaelManaged 
		$aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$aesAlg.KeySize = 256
		$aesAlg.BlockSize = 128
		$aesAlg.key = $key
		$aesAlg.IV = $iv

		# Create an encryptor to perform the stream transform.
		[System.Security.Cryptography.ICryptoTransform] $encryptor = $aesAlg.CreateEncryptor($aesAlg.Key, $aesAlg.IV);

		# Create the streams used for encryption.
		$msEncrypt = new-Object System.IO.MemoryStream
		$csEncrypt = new-object System.Security.Cryptography.CryptoStream($msEncrypt, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
		$swEncrypt = new-object System.IO.StreamWriter($csEncrypt)

		#Write all data to the stream.
		$swEncrypt.Write($plainText);
		$swEncrypt.Flush();
		$swEncrypt.Close();
	}
	finally
	{
		# Clear the RijndaelManaged object.
		if ($aesAlg -ne $null){
			$aesAlg.Clear();}
	}

	# Return the encrypted bytes from the memory stream.
	return $msEncrypt.ToArray();
}

function RandomByteArray([int] $length = 8)
{
	$array = @()
	for($i=0;$i -lt $length;$i++)
	{
		$array += [math]::Round($(Get-Random -Minimum 50.1 -Maximum 190.1))
	}
	return $array 
}

function OpenSSLDecrypt([String] $passphrase, [String] $encrypted) {
    # base 64 decode
    [byte[]] $encryptedBytesWithSalt = [Convert]::FromBase64String($encrypted);

    # extract salt (first 8 bytes of encrypted)
    [byte[]] $salt = $encryptedBytesWithSalt[8..15]

    [byte[]] $encryptedBytes = $encryptedBytesWithSalt[($salt.length + 8 )..($encryptedBytesWithSalt.Length)]
    #$encryptedBytes+=0
    # get key and iv
    $res = DeriveKeyAndIV $passphrase $salt
    [byte[]] $key = $res.key
    [byte[]] $iv = $res.iv

    return DecryptStringFromBytesAes $encryptedBytes $key $iv
}

function DecryptStringFromBytesAes([byte[]] $cipherText, [byte[]] $key, [byte[]] $iv) {
    # Check arguments.
    if ($cipherText -eq $null -or $cipherText.Length -le 0){
        throw  new-object ArgumentNullException("cipherText");}
    if ($key -eq $null -or $key.Length -le 0){
        throw  new-object ArgumentNullException("key");}
    if ($iv -eq $null -or $iv.Length -le 0){
        throw  new-object ArgumentNullException("iv");}

    # Declare the stream used to encrypt to an in memory
    # array of bytes.
    [System.IO.MemoryStream] $msDecrypt

    # Declare the RijndaelManaged object
    # used to encrypt the data.
    [System.Security.Cryptography.RijndaelManaged] $aesAlg = new-Object System.Security.Cryptography.RijndaelManaged

    [String] $plainText=""

    try  {
        # Create a RijndaelManaged object
        # with the specified key and IV.
        $aesAlg =  new-object System.Security.Cryptography.RijndaelManaged
        $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aesAlg.KeySize = 256
        $aesAlg.BlockSize = 128
        $aesAlg.key = $key
        $aesAlg.IV = $iv

        # Create an encryptor to perform the stream transform.
        [System.Security.Cryptography.ICryptoTransform] $decryptor = $aesAlg.CreateDecryptor($aesAlg.Key, $aesAlg.IV);

        # Create the streams used for encryption.
        $msDecrypt = new-Object System.IO.MemoryStream @(,$cipherText)
        $csDecrypt = new-object System.Security.Cryptography.CryptoStream($msDecrypt, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $srDecrypt = new-object System.IO.StreamReader($csDecrypt)

        #Write all data to the stream.
        $plainText = $srDecrypt.ReadToEnd()
        $srDecrypt.Close()
        $csDecrypt.Close()
        $msDecrypt.Close()
    }
    finally {
        # Clear the RijndaelManaged object.
        if ($aesAlg -ne $null){
            $aesAlg.Clear()
        }
    }

    # Return the Decrypted bytes from the memory stream.
    return $plainText
}


###example###
$passphrase = "some password"
$plaintext = "A lot of dummy plaintext,"
$encryptedText="$(OpenSSLEncrypt $passphrase $plainText)".Trim()
$encryptedText
$(OpenSSLDecrypt $passphrase $encryptedText)