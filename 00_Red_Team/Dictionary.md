

- **Credential stuffing** - a subset of the brute force attack category. Brute forcing will attempt to try multiple passwords against one or multiple accounts; guessing a password, in other words. Credential Stuffing typically refers to specifically using known (breached) username / password pairs against other websites.
	- mutiple passwords, one or more accounts
	- using previously leaked or stolen credentials
	- attempt to exploit accounts where passwords are reused for different sites/applications

- **Brute Force attacks** - A brute force attack can manifest itself in many different ways, but primarily consists in an attacker configuring predetermined values, making requests to a server using those values, and then analyzing the response. For the sake of efficiency, an attacker may use a dictionary attack (with or without mutations) or a traditional brute-force attack (with given classes of characters e.g.: alphanumeric, special, case (in)sensitive).

- **Password Spraying** - is a type of brute force attack. In this attack, an attacker will brute force logins based on list of usernames with default passwords on the application. For example, an attacker will use one password (say, Secure@123) against many different accounts on the application to avoid account lockouts that would normally occur when brute forcing a single account with many passwords.
	- one random/common password, multiple accounts
	- some people use reverse brute force and password spraying interchangeably

- **Dictionary Attack** - A type of brute force attack where an intruder attempts to crack a password-protected security system with a “dictionary list” of common words and phrases used by businesses and individuals. In a dictionary attack, the attacker utilizes a wordlist in the hopes that the user’s password is a commonly used word (or a password seen in previous sites). Dictionary attacks are optimal for passwords that are based on a simple word (e.g. 'cowboys' or 'longhorns'). Wordlists aren’t restricted to English words; they often also include common passwords (e.g. 'password,' 'letmein,' or 'iloveyou,' or '123456').
	- if you don't know username or password and are just guessing at both, this may be considered a dictionary attack

- **Reverse Brute Force** - In a usual BF attack, attackers do not know the password they are guessing. As the name implies, a reverse BF attack acts on in reverse. For example, if the attacker knows the PIN or password they are looking for, they will try to find the matching username by searching through millions of usernames. For this approach, attackers usually use passwords leaked by earlier data breaches that can be found online. This process can also be automated to speed up the attack.
	- know the password, but not the username
	- some people use reverse brute force and password spraying interchangeably

- **Mask Attack** - A mask attack is a type of brute forcing, where attackers know elements of a password construction and can therefore reduce the amount of guesses they’ll need to get it right. For example, an attacker might know a password is eight characters and the last one is a number. Or they might now a company has a poor policy such as adding the current month and year to the end of passwords when rotating them. Having any sort of definitive information about the makeup of a password can greatly speed up a hybrid attack.
	- if you're able to determine password policy and can build a wordlist based off that info