## 💻 About

- For a more secure network environment, self built Ca and self issued SSL certificate
- **Tip**  \[ [ssleye](https://www.ssleye.com/self_sign.html) ] \[ [myssl](https://myssl.com/create_test_cert.html) ]\[ [sslchecker](https://www.sslchecker.com/csr/self_signed) ] **online**

## ⚠️ danger

- If the same root certificate name exists in the database, the certificate in the database will be exported
- If the same service certificate name and (IP | Domain) exist in the database, the certificate in the database will be exported
- The domain name verification method uses setting temporary hosts to bypass DNS

## 👍 Help

### 0x01

```bash
./sslt -c US -h test.com
```

### 0x02

```bash
./sslt -r=ca.pem  -rk=/home/ca.key.pem -h="1.1.1.1" -sc="This is DNS"
```

### 0x03

```bash
./sslt -c US -h 1.1.1.1 -so "证书的名字，方便记忆"
```

### 0x05

```bash

./sslt -c US -h test.com -rc "Root CommonName" -ro "Root OrganizationName" -sc "Server CommonName" -so "Server OrganizationName"
```

### help

```bash
➜  ~ ./sslt -help
 -------------------------------
   _____   _____  .      _______
  (       (      /     '   /
   `--.    `--.  |         |
      |       |  |         |
 \___.'  \___.'  /---/     /
 ----------------------
flag needs an argument: -h
Usage of sslt:
  -c string
    	Specified Country (default "US")
  -h string
    	Specified domain name (default "baidu.com")
  -help
    	Display help information
  -r string
    	Import Root_CA (default "default")
  -rc string
    	Specified Root CommonName (default "GTS Root R1")
  -rk string
    	Import Root_CA Key (default "default")
  -ro string
    	Specified Root Organization (default "Google Trust Services LLC")
  -sc string
    	Specified Server CommonName (default "GTS CA 1C3")
  -so string
    	Specified Server Organization (default "Google Trust Services LLC")
  -v	sslt version
```

## 😊 Thanks 

\[ [shaneutt](https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251) ]  \[  [AndroidOL](https://post.m.smzdm.com/p/715145/) ]  \[ [I3estD4rkKn1ght](https://github.com/I3estD4rkKn1ght) ]
