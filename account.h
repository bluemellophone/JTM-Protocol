#include <string>
#include <vector>

using std::string;

class Account {
	private:
		string username;
		int accountNumber;
		int pin;
		float balance;
		int loginAttempts;
		int timeout;

	public:
		Account () {}
		Account (string un, int num, int p, float b)
		{
			username = un;
			accountNumber = num;
			pin = p;
			balance = b;
			loginAttempts = 0;
			timeout = 0;
		}
		string get_un () { return username; }
		int get_account () { return accountNumber; }
		int get_pin () { return pin; }
		float get_balance () { return balance; }
		int get_login () { return loginAttempts; }
		void increase_balance (float b) { balance += b; }
		void reduce_balance (float b) { balance -= b; }
		void increment_login () { loginAttempts++; }
}; 	

static Account alice ("alice", 12345, 1234, 100.00);
static Account bob ("bob", 67890, 6789, 50.00);
static Account eve ("eve", 13579, 2468, 0);

std::vector<Account> init() 
{
	std::vector<Account> db;
	db.push_back (alice);
	db.push_back (bob);
	db.push_back (eve);

	return db;
}

static std::vector<Account> Database = init();
