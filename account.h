
#include "util.h"

class Account {
	private:
		std::string username;
		std::string accountNumber;
		int pin;
		float balance;
		bool logged_in;
		float dailyDeposit;
		float dailyWithdraw;
		float dailyTransfer;

	public:
		Account () {}
		Account (std::string un, std::string num, int p, float b)
		{
			username = un;
			accountNumber = num;
			pin = p;
			balance = b;
			logged_in = false;
			dailyDeposit = 0;
			dailyWithdraw = 0;
			dailyTransfer = 0;
		}
		std::string get_un () { return username; }
		std::string get_account () { return accountNumber; }
		int get_pin () { return pin; }
		float get_balance () { return balance; }
		void increase_balance (float b) { balance += b; }
		void reduce_balance (float b) { balance -= b; }
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

static Account alice ("alice", getCardHash("cards/alice.card"), 123456, 100.00);
static Account bob ("bob", getCardHash("cards/bob.card"), 678900, 50.00);
static Account eve ("eve", getCardHash("cards/eve.card"), 246800, 0);

std::vector<Account> init() 
{
	std::vector<Account> db;
	db.push_back (alice);
	db.push_back (bob);
	db.push_back (eve);

	return db;
}

static std::vector<Account> Database = init();
