############################################################

Class: Cryptography and Network Security I
Group Members: Jason Parham, Tyler Cassetta-Frey, Matt O'Brien

############################################################

To compile Crypto++ static library and project:

1.) cd includes/cryptopp/
2.) make -j4 libcryptopp.a 
3.) cd ../.. 
4.) make

############################################################


--------------------- Project Elements ---------------------

Crypto Libraries: Crypto++ [http://www.cryptopp.com/]

Symmetric Encryption: AES-256
	256-bit (32-character) Session Key, discarded after every logout
	128-bit (16-character) Session Block, discarded after every logout

Asymmetric Encryption: RSA (Two-way Authentication & Confidentiality)
	Public and Private Keys for ATM
	Public and Private Keys for Bank

Hash Function: SHA-512
	128-character Hexidecimal Hash

Nonces: Two-Way
	256-bit (32-character) Bank Nonce
	256-bit (32-character) ATM Nonce

Withdraw Limits = $1000 per day
Deposit Limits = $1000 per day
Transfer Limit = $1000 per day

--------------------- Project Data Structures ---------------------

Handshakes
	ATM Handshake = "handshake", New / First ATM Nonce, Random Padding to (512 - 128 - 1)
	Hashed ATM Handshake = ATM Handshake, 128 Character SHA-512 ATM Handshake Hash 
	RSA Encrypted, Encoded ATM Handshake = Base64Encoding[ Encrypt^RSA-BANK PUBLIC KEY( Hashed ATM Handshake ) ]

	Bank Handshake = "handshake", Last ATM Nonce, New / First Bank Nonce, AES Session Key, AES Session Block, Random Padding to (512 - 128 - 1)
	Hashed Bank Handshake = Bank Handshake, 128 Character SHA-512 Bank Handshake Hash 
	RSA Encrypted, Encoded Bank Handshake = Base64Encoding[ Encrypt^RSA-ATM PUBLIC KEY( Hashed Bank Handshake ) ]

	Handshake Length = 512 Characters
	RSA Encrypted, Encoded Handshake Length = 1039 Characters

Messages
	ATM Message = Command, Username, Card Number Hash, Pin, Dollar Amount, Transfer Username, New ATM Nonce, Last Bank Nonce, Random Padding to (1023 - 128 - 1)
	Bank Message = Command, Status, Last ATM Nonce, New Bank Nonce, Random Padding to (1023 - 128 - 1)
	
	Message Length = 1023-character Total Hashed Message Length - 128-character Message Hash - 1-character comma deliminator = 894 Characters

	Hashed Message = Message, 128 Character SHA-512 Message Hash
	Hashed Messgage Length = 1023 Characters

	AES Encrypted, Encoded Packet = Base64Encoding[ Encrypt^AES-SESSION KEY( Hashed Message ) ]
	AES Encrypted, Encoded Packet Length = 1408 Characters

	ATM Messages
		login, Username Hash, Card Number Hash, Pin Hash, NOT USED, NOT USED, New ATM Nonce, HANDSHAKE BANK NONCE
		balance, Username Hash, Card Number Hash, Pin Hash, NOT USED, NOT USED, New ATM Nonce, Last Bank Nonce
		withdraw, Username Hash, Card Number Hash, Pin Hash, Amount to Withdraw, NOT USED, New ATM Nonce, Last Bank Nonce
		transfer, Username Hash, Card Number Hash, Pin Hash, Amount to Transfer, Transfer Username Hash, New ATM Nonce, Last Bank Nonce
		logout, Username Hash, Card Number Hash, Pin Hash, NOT USED, NOT USED, New ATM Nonce, Last Bank Nonce

	Bank Messages
		login, If login successful, Last ATM Nonce, New Bank Nonce
		balance, Dollar amount of balance, Last ATM Nonce, New Bank Nonce
		withdraw, Dollar amount to withdraw, Last ATM Nonce, New Bank Nonce
		transfer, If transfer successful, Last ATM Nonce, New Bank Nonce
		logout, If logout successful, Last ATM Nonce, New Bank Nonce


Card Files: 128-character SHA-512 Hash
	* Card hashes do not include the spaces from the card number.

	Alice's Card (alice.card)
		Account PIN: 123456
		Account / Card Number: 6767 8173 9049 1823
		Account / Card Hash: 6A0A94E1F7AF7EA1371841327596A848FC7C8FDF32B6E30620138CC30D7340F229389A8DD6DF6168C71151E9F774499C78888BE2F13D3A7212C519F4F0D3C9AA

	Bob's Card (bob.card)
		Account PIN: 6789 (678900)
		Account / Card Number: 6767 2538 0275 1281
		Account / Card Hash: 4A186EE6BC856F30BFB8C6E1971941D84D9F7679A70B46F95F9490A9907D44902473A37F127727AA206B5F2705F71A2C07543D4AC706E57233D60EEDD6146458

	Eve's Card (eve.card)
		Account PIN: 2468 (246800)
		Account / Card Number: 6767 4248 6174 1091
		Account / Card Hash: 3B79391F77F14C0D512E996F6778C6B093A05F5807107CC060790D59D21C734357BAA569D147DCE412BBE3C533240C0A61BF1F0D190C76118D99D5CDBA15FF98

