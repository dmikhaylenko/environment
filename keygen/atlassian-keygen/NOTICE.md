To install M2Crypto on Mac OS X El Capitan:

```
env LDFLAGS="-L$(brew --prefix openssl)/lib" \
CFLAGS="-I$(brew --prefix openssl)/include" \
SWIG_FEATURES="-cpperraswarn -includeall -I$(brew --prefix openssl)/include" \
pip install m2crypto
```

refer: http://stackoverflow.com/questions/33005354/trouble-installing-m2crypto-with-pip-on-el-capitan
