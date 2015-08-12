[overview]
-------------------------------------------------------------------------------
demoncrypt 2.0
Believe in the Right to Share
Copyright 2014-2015 Demonsaw LLC All Rights Reserved
https://www.demonsaw.com

Demoncrypt is a lightweight C++ wrapper around some of the more common crypto routines in Crypto++.  Demoncrypt is the open-source crypto layer used in demonsaw.  It's free and open-source.  Use it however you want.

[prerequisites]
-------------------------------------------------------------------------------
* C++ 11 compliant compiler (gcc 4.7, MSVC 2013, or greater)
* Cryptop++ 5.6.2 (www.cryptopp.com)

[contents]
-------------------------------------------------------------------------------
/security/
	aes.h
	base.h
	block_cipher.cpp
	block_cipher.h
	checksum.h
	diffie_hellman.cpp
	diffie_hellman.h
	filter.h
	hash.h
	hex.h
	hmac.h
	md.h
	pbkdf.h
	security.cpp
	security.h
	sha.h
/system/
	type.h

[setup]
-------------------------------------------------------------------------------
Just copy the security and system folders into your project workspace.  Update your project/solution/makefiles accordingly.  Include the appropriate files in your *.h/*.cpp source.  Build.  Enjoy!

[questions]
https://twitter.com/demon_saw
eijah@demonsaw.com


-Eijah
