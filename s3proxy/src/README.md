# How to build and run

## 1) Docker way
```sh
mkdir -p ~/go && cd ~/go
git clone https://github.com/alsarins/aws_s3.git
cd aws_s3/s3proxy/src
sudo docker build -t s3proxy .

# check result
docker images

# copy and edit config
cp .s3proxy-encrypted.cfg ~/.s3proxy.cfg
# edit ~/.s3proxy.cfg with own AccessKey,SecretAccessKey,EncryptionKey and other params

# start and check
docker run -d --name s3proxy -p 18000:18000 -v ~/.s3proxy.cfg:/etc/s3proxy.cfg s3proxy
docker logs s3proxy
```

## 2) Compile and install from sources
**install go 1.23 for linux if not present**
```sh
# attention here!
# sudo rm -rf /usr/local/go
wget https://go.dev/dl/go1.23.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.5.linux-amd64.tar.gz
rm -f go1.23.5.linux-amd64.tar.gz
```

**create workdir and clone repo**

```sh
mkdir -p ~/go && cd ~/go
git clone https://github.com/alsarins/aws_s3.git
```


**add env vars into ~/.bashrc i.e:**
```sh
export GOPATH=$HOME/go
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin:$HOME/go/bin
export GO111MODULE=on
export CGO_ENABLED=0
source ~/.bashrc
```

**check go is working**
```sh
go version
```

**build app**
```
cd <CLONE_DIR>/aws_s3/s3proxy/src/
make clean
go mod tidy
go mod verify
make build
```

**install s3proxy**
```sh
# The following command will copy binary into /usr/local/bin/s3proxy if you have sudo privileges
# if not - change Makefile for your environment

make install
```

**start it and check**
```sh
# start as foreground process with logging into STDOUT
s3proxy -debug=true ~/s3proxy.cfg
```
