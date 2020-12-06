.PHONY: clean

#### Main executable program
sendfile: sendfile.cpp
	gcc -Wall -Wextra sendfile.cpp -o sendfile -lstdc++

# Remove the executable and any temporary compilation files
clean:
	rm -f sendfile