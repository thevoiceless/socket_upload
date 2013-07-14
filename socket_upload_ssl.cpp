// Largely based off of https://github.com/polarssl/polarssl/blob/master/programs/ssl/ssl_client1.c

#include <iostream>
#include <cstdlib>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>

#include "polarssl/config.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/error.h"
#include "polarssl/certs.h"
#include "polarssl/sha1.h"
#include "polarssl/md5.h"

using namespace std;

static const string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ssl_context ssl;
x509_cert cacert;
entropy_context entropy;
ctr_drbg_context ctr_drbg;

int ret, server_fd;
unsigned char buf[1536];
const char* identity = "socket upload script";

// SSL-related cleanup
void cleanUp()
{
	x509_free(&cacert);
	net_close(server_fd);
	ssl_free(&ssl);
	memset(&ssl, 0, sizeof(ssl));
}

// Clean up and exit with the given return code
int finish(int ret)
{
	// PolarSSL has some fancy error logic
#ifdef POLARSSL_ERROR_C
	if (ret != 0)
	{
		char error_buf[512];
		error_strerror(ret, error_buf, 512);
		cout << "Last error was: " << ret << " - " << error_buf << endl;
	}
#endif

	cleanUp();
	exit(ret);
}

// Read all of the bytes from the given file and return them as a vector of characters
vector<char> readAllBytes(const char* filename)
{
	// Open the file in binary mode, starting at the end
	ifstream infile(filename, ios::binary | ios::ate);
	if (infile.fail())
	{
		cout << "Failed to open file " << filename << endl;
		cleanUp();
		exit(1);
	}

	// The current position is at the end of the file, so tellg() will return its size
	ifstream::pos_type size = infile.tellg();
	vector<char> result(size);

	// Return to the beginning of the file and read its contents
	infile.seekg(0, ios::beg);
	infile.read(&result[0], size);

	return result;
}

// Return the current GMT date and time for use in the HTTP header
string currentDateTime()
{
	time_t rawtime;
	struct tm* tstruct;
	time(&rawtime);
	tstruct = gmtime(&rawtime);
	char buf[80];

	strftime(buf, sizeof(buf), "%a, %d %b %Y %X +0000", tstruct);

	return buf;
}

// Encode the given bytes in base-64 and return them as a string
// http://www.adp-gmbh.ch/cpp/common/base64.html
string base64_encode(const unsigned char* bytes_to_encode, unsigned int in_len)
{
	string ret;
	int i = 0;
	int j = 0;
	unsigned char char_array_3[3];
	unsigned char char_array_4[4];

	while (in_len--)
	{
		char_array_3[i++] = *(bytes_to_encode++);
		if (i == 3)
		{
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
			{
				ret += base64_chars[char_array_4[i]];
			}
			i = 0;
		}
	}

	if (i)
	{
		for (j = i; j < 3; j++)
		{
			char_array_3[j] = '\0';
		}

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; j < i + 1; j++)
		{
			ret += base64_chars[char_array_4[j]];
		}

		while (i++ < 3)
		{
			ret += '=';
		}
	}

	return ret;
}

int main(int argc, char* argv[])
{
	string hostname;
	int port;
	string file;

	if (argc != 4)
	{
		cerr << "Usage: " << argv[0] << " HOSTNAME PORT FILE" << endl;
		exit(1);
	}
	else
	{
		hostname = string(argv[1]);
		port = atoi(argv[2]);
		file = string(argv[3]);
	}
	cout << "PUT " << file << " at " << hostname << ":" << port << endl;

	// Initialize the RNG and the session data
	memset(&ssl, 0, sizeof(ssl_context));
	memset(&cacert, 0, sizeof(x509_cert));

	cout << "  . Seeding the random number generator...";
	entropy_init(&entropy);
	if ((ret = ctr_drbg_init(&ctr_drbg,
		entropy_func, 
		&entropy,
		(const unsigned char*) identity,
		strlen(identity))) != 0)
	{
		cout << " failed" << endl << "  ! ctr_drbg_init returned" << ret << endl;
		finish(ret);
	}
	else
	{
		cout << " OK" << endl;
	}

	// Initialize certificates
	cout << "  . Loading the CA root certificate...";

#if defined(POLARSSL_CERTS_C)
	ret = x509parse_crt(&cacert, (const unsigned char*) test_ca_crt, strlen(test_ca_crt));
#else
	ret = 1;
	cout << "POLARSSL_CERTS_C not defined.";
#endif

	if (ret < 0)
	{
		cout << " failed" << endl << "  ! x509parse_crt returned -0x" << hex << ret << endl << endl;
		finish(ret);
	}
	else
	{
		cout << " OK (" << ret << " skipped)" << endl;
	}

	// Try to connect
	cout << "  . Connecting to " << hostname << " on port " << port << "...";

	if ((ret = net_connect(&server_fd, hostname.c_str(), port)) != 0)
	{
		cout << " failed" << endl << "  ! net_connect returned " << ret << endl << endl;
		finish(ret);
	}
	else
	{
		cout << " OK" << endl;
	}

	// Prepare SSL
	cout << "  . Preparing the SSL/TLS structure...";
	if ((ret = ssl_init(&ssl)) != 0)
	{
		cout << " failed" << endl << "  ! ssl_init returned " << ret << endl << endl;
		finish(ret);
	}
	else
	{
		cout << " OK" << endl;
	}

	ssl_set_endpoint(&ssl, SSL_IS_CLIENT);
	ssl_set_authmode(&ssl, SSL_VERIFY_OPTIONAL);
	ssl_set_ca_chain(&ssl, &cacert, NULL, "s3.amazonaws.com");
	ssl_set_rng(&ssl, ctr_drbg_random, &ctr_drbg);
	ssl_set_bio(&ssl, net_recv, &server_fd, net_send, &server_fd);

	// Handshake
	cout << "  . Performing the SSL/TLS handshake...";
	while ((ret = ssl_handshake(&ssl)) != 0)
	{
		if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			cout << " failed" << endl << "  ! ssl_handshake returned -0x" << hex << ret << endl << endl;
			finish(ret);
		}
	}
	cout << " OK" << endl;

	// Verify the certificate
	cout << "  . Verifying certificate...";
	if ((ret = ssl_get_verify_result(&ssl)) != 0)
	{
		cout << " failed" << endl;
		if ((ret & BADCERT_EXPIRED) != 0)
		{
			cout << "  ! Server certificate has expired" << endl;
		}
		if ((ret & BADCERT_REVOKED) != 0)
		{
			cout << "  ! server certificate has been revoked" << endl;
		}
		if ((ret & BADCERT_CN_MISMATCH) != 0)
		{
			cout << "  ! CN mismatch" << endl;
		}
		if ((ret & BADCERT_NOT_TRUSTED) != 0)
		{
			cout << "  ! self-signed or not signed by a trusted CA" << endl;
		}
	}
	else
	{
		cout << " OK" << endl;
	}

	/*
	 * Build the PUT request
	 * http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectPUT.html
	 * http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheAuthenticationHeader
	 */
	// Extract only the file name
	int spot = file.rfind("/");
	if (spot == string::npos)
	{
		spot = file.rfind("\\");
		if (spot == string::npos)
		{
			spot = 0;
		}
	}
	// Read all bytes from the file
	vector<char> fileBytes = readAllBytes(file.c_str());
	string fileContents(fileBytes.begin(), fileBytes.end());

	// AWS key must be set in an environment variable
	char* awskey_env = getenv("AWS_KEY");
	if (!awskey_env)
	{
		cout << "No AWS key set in environment vars" << endl;
		cleanUp();
		exit(1);
	}
	string awskey(awskey_env);

	// Get current time
	string now = currentDateTime();

	// Construct Amazon's StringToSign element
	ostringstream stringToSign;
	stringToSign << "PUT\n";                        // HTTP verb
	stringToSign << "\n";                           // MD5
	stringToSign << "application/octet-stream\n";   // Content type
	stringToSign << now << "\n";                    // Date

	// Construct Amazon's CanonicalizedResource element
	ostringstream canonicalizedResource;
	canonicalizedResource << "/" + hostname.substr(0, hostname.find_first_of('.')); // Bucket name preceded by a '/'
	canonicalizedResource << file.substr(spot, string::npos);                       // Path

	// Add CanonicalizedResource to StringToSign
	// NOTE: Does not include CanonicalizedAmzHeaders element
	stringToSign << canonicalizedResource.str();

	// Calculate the HMAC-SHA1 of the access key with the StringToSign element
	// NOTE: Does not guarantee that StringToSign is in UTF-8 encoding
	const unsigned char* u_awskey = reinterpret_cast<const unsigned char*>(awskey.c_str());
	const unsigned char* u_stringToSign = reinterpret_cast<const unsigned char*>(stringToSign.str().c_str());
	unsigned char sha1hmacOutput[20];
	sha1_hmac(u_awskey, awskey.length(), u_stringToSign, stringToSign.str().length(), sha1hmacOutput);

	// Create the HTTP header
	ostringstream header;
	header << "PUT " << file.substr(spot, string::npos) << " HTTP/1.1\r\n";
	header << "Content-Type: application/octet-stream\r\n";
	header << "Content-Length: " << fileContents.size() << "\r\n";
	header << "Host: " << hostname << "\r\n";
	header << "Date: " << now << "\r\n\r\n";
	// HMAC-SHA1 output must be encoded in base-64
	header << "Authorization: AWS " << awskey << ":" << base64_encode(sha1hmacOutput, 20) << "\r\n\r\n";

	string headerString = header.str();
	// cout << headerString << endl;
	// cout << fileContents << endl;

	// Send the request
	cout << "  . Sending request..." << endl;
	// Send header first
	int len = sprintf((char*) buf, headerString.c_str());
	while ((ret = ssl_write(&ssl, buf, len)) <= 0)
	{
		if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			cout << " failed" << endl << "  ! ssl_write returned " << ret << endl << endl;
			finish(ret);
		}
	}
	cout << "  + " << ret << " header bytes sent" << endl;
	cout.flush();
	// Then send the contents
	// For some reason this was necessary to ensure that the entirety of fileContents was sent
	const unsigned char* contents = reinterpret_cast<const unsigned char*>(fileContents.c_str());
	while ((ret = ssl_write(&ssl, contents, fileContents.size())) <= 0)
	{
		if (ret != POLARSSL_ERR_NET_WANT_READ && ret != POLARSSL_ERR_NET_WANT_WRITE)
		{
			cout << " failed" << endl << "  ! ssl_write returned " << ret << endl << endl;
			finish(ret);
		}
	}
	cout << "  + " << ret << " content bytes sent" << endl;
	cout.flush();

	// Read the response
	cout << "  . Reading from server...";
	cout.flush();
	while (true)
	{
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = ssl_read(&ssl, buf, len);

		if (ret == POLARSSL_ERR_NET_WANT_READ || ret == POLARSSL_ERR_NET_WANT_WRITE)
		{
            continue;
		}

        if (ret == POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            break;
        }

        if (ret < 0)
        {
        	cout << " failed" << endl << "  ! ssl_read returned " << ret << endl << endl;
            finish(ret);
        }

        if (ret == 0)
        {
        	cout << endl << endl << "EOF" << endl << endl;
            break;
        }

        len = ret;
        cout << len << " bytes read" << endl << endl << buf << endl;
        cout.flush();
	}

	// Finish
	cout << "  . Closing connection...";
	cout.flush();
	ssl_close_notify(&ssl);
	cout << "done" << endl;

	cleanUp();
	exit(ret);
}