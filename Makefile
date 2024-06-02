all:
		g++ sdb.cpp -o sdb /usr/local/lib/libZydis.a
clean:
		rm sdb
