SerpentStream: SerpentStream.cpp SerpentCounter.cpp
	g++ -std=c++0x -c -o SerpentCounter.o SerpentCounter.cpp
	g++ -std=c++0x -c -o SerpentStream.o SerpentStream.cpp  
	g++ -std=c++0x -o SerpentStream SerpentCounter.o SerpentStream.o


# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:
#
clean: 
	$(RM) Serpent SerpentOptimizedFinal SerpentStream *.o *~
