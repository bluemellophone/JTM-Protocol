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
		bool logged_in;
		float dailyDeposit;
		float dailyWithdraw;
		float dailyTransfer;

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
			logged_in = false;
			dailyDeposit = 0;
			dailyWithdraw = 0;
			dailyTransfer = 0;
		}
		string get_un () { return username; }
		int get_account () { return accountNumber; }
		int get_pin () { return pin; }
		float get_balance () { return balance; }
		int get_loginAttempts () { return loginAttempts; }
		void increase_balance (float b) { balance += b; }
		void reduce_balance (float b) { balance -= b; }
		void increment_login () { loginAttempts++; }
		bool get_logged_in () { return logged_in; }
		void set_logged_in_true () { logged_in = true; }
		void set_logged_in_false () { logged_in = false; }
		float get_deposit () { return dailyDeposit; }
		float get_withdraw () { return dailyWithdraw; }
		float get_transfer () { return dailyTransfer; }
		void increase_deposit (float val) { dailyDeposit += val; }
		void increase_withdraw (float val) { dailyWithdraw += val; }
		void increase_transfer (float val) { dailyTransfer += val; }
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
