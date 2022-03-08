## 💻 About

- For a more secure network environment, self built Ca and self issued SSL certificate
- **Tip**  \[ [ssleye](https://www.ssleye.com/self_sign.html) ] \[ [myssl](https://myssl.com/create_test_cert.html) ]\[ [sslchecker](https://www.sslchecker.com/csr/self_signed) ] **online**

## ⚠️ danger

- If the same root certificate name exists in the database, the certificate in the database will be exported
- If the same service certificate name and (IP | Domain) exist in the database, the certificate in the database will be exported
- The domain name verification method uses setting temporary hosts to bypass DNS

## ☂️ How to use

### 0x01

```bash
./sslt -c US -h="test.com 1.1.1.1 localhost" -sc="This is DNS"
```

### 0x02

```bash
./sslt -r=ca.pem  -rk=/home/ca.key.pem
```

### 0x03

```bash
./sslt -c US -h 1.1.1.1 -sc "证书的名字，方便记忆"
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
Usage of sslt:
  -c string
        Specified Country (default "US")
  -h string
        Specified domain name (default "localhost")
  -help
        Display help information
  -p string
        Specified encryption protocol (default "rsa")
  -r string
        Import CA (default "default")
  -rc string
        Specified Root CommonName (default "GTS Root R1")
  -rk string
        Import CA Key (default "default")
  -ro string
        Specified Root Organization (default "Google Trust Services LLC")
  -s string
        Import Server (default "default")
  -sc string
        Specified Server CommonName (default "GTS CA 1C3")
  -sk string
        Import Server Key (default "default")
  -so string
        Specified Server Organization (default "Google Trust Services LLC")
  -v    sslt version
 -------------------------------
```

## 😊 Thanks

\[ [shaneutt](https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251) ]  \[  [AndroidOL](https://post.m.smzdm.com/p/715145/) ]  \[ [I3estD4rkKn1ght](https://github.com/I3estD4rkKn1ght) ]