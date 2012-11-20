#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
using std::string;

string Hex(string inputStr)
{
    string retStr = "";
    for(int i = 0; i < inputStr.length(); i++)
    {
        if(('0' <= inputStr[i] && inputStr[i] <= '9') || ('A' <= inputStr[i] && inputStr[i] <= 'F'))
        {
            retStr += inputStr[i];
        }
        else
        {
            retStr += "0";
        }
    }

    return retStr;
}

class Account {
	private:
		string username;
		string accountNumber;
		int pin;
		float balance;
		bool logged_in;
		float dailyDeposit;
		float dailyWithdraw;
		float dailyTransfer;

	public:
		Account () {}
		Account (string un, string num, int p, float b)
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
		string get_un () { return username; }
		string get_account () { return accountNumber; }
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


string aHash () {
	string cardHash;
	std::ifstream aCard ("cards/alice.card");
	string aliceCard((std::istreambuf_iterator<char>(aCard)),std::istreambuf_iterator<char>());
	cardHash = aliceCard;
	cardHash = cardHash.substr(0,128);
	std::transform(cardHash.begin(), cardHash.end(), cardHash.begin(), ::toupper);
	cardHash = Hex(cardHash);
	return cardHash;
}

static Account alice ("alice", aHash(), 123456, 100.00);


string bHash () {
	string cardHash;
	std::ifstream bCard ("cards/bob.card");
	string bobCard((std::istreambuf_iterator<char>(bCard)),std::istreambuf_iterator<char>());
	cardHash = bobCard;
	cardHash = cardHash.substr(0,128);
	std::transform(cardHash.begin(), cardHash.end(), cardHash.begin(), ::toupper);
	cardHash = Hex(cardHash);
	return cardHash;
}

static Account bob ("bob", bHash(), 678900, 50.00);

string eHash() {
	string cardHash;
	std::ifstream eCard ("cards/eve.card");
	string eveCard((std::istreambuf_iterator<char>(eCard)),std::istreambuf_iterator<char>());
	cardHash = eveCard;
	cardHash = cardHash.substr(0,128);
	std::transform(cardHash.begin(), cardHash.end(), cardHash.begin(), ::toupper);
	cardHash = Hex(cardHash);
	return cardHash;
}

static Account eve ("eve", eHash(), 246800, 0);

std::vector<Account> init() 
{
	std::vector<Account> db;
	db.push_back (alice);
	db.push_back (bob);
	db.push_back (eve);

	return db;
}

static std::vector<Account> Database = init();
