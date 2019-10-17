# The JSON Web Token PWNing Toolkit
>*jwt_PWN.py* is a toolkit for validating, forging and cracking JWTs (JSON Web Tokens).  


Features:
- Checking the validity of a token (Only HMAC-SHA)
- Testing for the ***RS/HS256*** public key mismatch vulnerability
- Testing for the ***alg=none*** signature-bypass vulnerability
- Identifying ***weak keys*** via ***Dictionary Attack*** 
- Forging tokens header and payloads

## Requirements
Python 3, that's it.

## Usage
`$  python3 JWT_pwn.py <token>`  

The first argument should be the JWT itself.

**For example:**  
`$ python jwt_PWN.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`


## Further Reading
* [A great intro to JWTs - https://jwt.io/introduction/](https://jwt.io/introduction/)

* A lot of the inspiration for this tool comes from the vulnerabilities discovered by Tim McLean.  
[Check out his blog on JWT weaknesses here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

## Tips
**Regex for finding JWTs in Burp Search**  
*(make sure 'Case sensitive' and 'Regex' options are ticked)*  
`[= ]ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*` - url-safe JWT version  
`[= ]ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*` - all JWT versions (higher possibility of false positives)

##TODO
-Support RSA signed tokens
-Multithread cracking of keys(Probably with a module written in Go)