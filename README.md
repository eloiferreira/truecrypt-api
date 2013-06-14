truecrypt-api
=============

This is a project to create a programmatic API layer for [TrueCrypt](http://www.truecrypt.org/ "www.truecrypt.org").

##Raison d'être##

TrueCrypt does have a decent command-line interface which provides adequately for automation tasks. Its usability in programming context has its limitations though. This is the main reason for my attempt to create a programmatic API layer for TrueCrypt. Such layer in form of a dll could then be used in a convenient way from just about any language on Windows platform, providing for added TrueCrypt extensibility.

##Important notes##

It is clear that one of the most important properties of TrueCrypt is it's [confirmed resistance](http://www.webcitation.org/query?url=g1.globo.com/English/noticia/2010/06/not-even-fbi-can-de-crypt-files-daniel-dantas.html "Even the FBI was not able to decrypt a TrueCrypt volume after a year of trying") to breaking attempts. This characteristic owes much to the fact the source code was [analyzed by many interested parties](http://www.truecrypt.org/faq "TrueCrypt is open-source, but has anybody actually reviewed the source code?") and apparently found solid. This makes modification of TrueCrypt's code a very undesirable option. 

Still, a lot of TrueCrypt's functional code is located in two end-user applications where it gets densely interspersed with GUI- and control-related code. This makes clean functional extension impossible. Though there is of course a number of feasible ways to achieve stated goal while leaving the original code untouched, the result in none of them can be considered acceptable.

This is the basis of my decision to refactor TrueCrypt code as I see fit while pursuing the following targets:

- No encryption algorithms-related code should be modified in any way
- Functional code should be reused with minimal possible modifications
- Security-conscious approach should be preserved by new code
- TrueCrypt driver modification should not become necessary
- No GUI or otherwise unrelated to API code should be included in resulting dll
- The resulting dll should work with existing installation of TrueCrypt

##Compatibility##

This project aims to be compatible with TrueCrypt 7.1a driver. 

##Limitations##

Although TrueCrypt supports several platforms, current target platform of this project is Windows Vista and above.

UPD: 2013-06-15 Currently working on another project