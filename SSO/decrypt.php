<?php


function ssoDecryptCRM($payload, $ssoKey)
{
    function evp_bytes_to_key($password, $salt)
    {
        $key = '';
        $iv = '';
        $derived_bytes = '';
        $previous = '';

        // Concatenate MD5 results until we generate enough key material (32 bytes key + 16 bytes IV = 48 bytes)
        while (strlen($derived_bytes) < 48) {
            $previous = md5($previous . $password . $salt, true);
            $derived_bytes .= $previous;
        }

        // Split the derived bytes into the key (first 32 bytes) and IV (next 16 bytes)
        $key = substr($derived_bytes, 0, 32);
        $iv = substr($derived_bytes, 32, 16);

        return [$key,
            $iv];
    }
    try {
        $ciphertext = base64_decode($payload);
        // Check for the "Salted__" prefix and extract the salt (next 8 bytes)
        if (substr($ciphertext, 0, 8) !== "Salted__") {
            return null;
        }
        $salt = substr($ciphertext, 8, 8);

        // The actual ciphertext (after "Salted__" and salt)
        $ciphertext = substr($ciphertext, 16);

        // Derive key and IV using the same method as CryptoJS
        list($key, $iv) = evp_bytes_to_key($ssoKey, $salt);
        $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        // Check for decryption success and return object
        if ($decrypted === false) {
            //echo 'Decryption failed: ' . openssl_error_string();
            return null;
        } else {
            return json_decode($decrypted);
        }
    } catch (Exception $e) {
        return null;
    }
}

$encrypted_data = 'U2FsdGVkX183Dt/hSF9MFp6YSz3b/oUbkLbbxZsJEy8DO0SEdAnyAX8Pxy8vhQQapKpGxeMb12luDT/qqsacGV+6EI8KRmByhxaC37AbLJU1bsyLYVQO0J618AZvOYTaxbYSD0k2AL5mOzlW5QnHU0ZOAtlPqM6YmFnx8RJo8cZ2BsTseDSXk+F5iZa5hS0YFWMrgNOGCr5l8W+yT3KZg5eveEONr8q+NNWxsMNwPe2A+yjT59/o/wL3IBAEYrOX7GpMiK7qrvxQIEeLwBa5EVQssYNXR8z+S8U+f8B19ME=';

$key = '376369c7-66d3-sssss'; // Generate SSO key from markteplace.gohighlevel.com app

$data = ssoDecryptCRM($encrypted_data, $key);
echo json_encode($data);
?>
