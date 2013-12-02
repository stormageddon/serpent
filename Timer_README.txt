The timer needed for testing is already in its own class, the functions can be copied into our program, but it can also be implemented as is with the following steps.

1.	use the code **#include "Timer.cpp"** (minus the '*' characters) to import all of the relevant functions.
2.	use the block of code:
	**Timer test;
	  test.StartTimer();

	  //DO STUFF

	  double result = test.EndTimer();
	  std::cout << result << " Milliseconds needed to do stuff." << std::endl;**
