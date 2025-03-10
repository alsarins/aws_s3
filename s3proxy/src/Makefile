# Имя бинарного файла
BINARY=s3proxy

# Цель по умолчанию
.PHONY: all
all: build

# Цель для сборки
build:
	go build -o $(BINARY)

# Цель для установки
.PHONY: install
install: build
	sudo cp $(BINARY) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY)

# Цель для очистки
.PHONY: clean
clean:
	rm -f $(BINARY)

