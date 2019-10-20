main: 
	ghc -Wall -Werror Main.hs
	mv Main parse_quote

.PHONY: clean

clean:
	rm Main.o Main.hi parse_quote
