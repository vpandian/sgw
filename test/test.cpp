#include <iostream>
#include <pqxx/pqxx> 
#include <sys/time.h>
using namespace std;
using namespace pqxx;

int main(int argc, char* argv[])
{
  char * sql;
  cout << "It is working" << endl;
   try{
     connection C("dbname=segw user=postgres password=vijay  \
      hostaddr=127.0.0.1 port=5432");
     if (C.is_open()) 
	{
	  cout << "Opened database successfully: " << C.dbname() << endl;
	} 
      else 
	{
	  cout << "Can't open database" << endl;
	  return 1;
	}

     /* Create SQL statement */
      sql = "SELECT ip from endpoint where port = 2";

      /* Create a non-transactional object. */
      nontransaction N(C);
      
      timeval begin;
      gettimeofday(&begin,NULL);
      /* Execute SQL query */
      result R( N.exec( sql ));
      int count = 0;
      /* List down all the records */

      for (result::const_iterator c = R.begin(); c != R.end(); ++c) 
	{
	  //cout << "IP = " << c[0].as<int>() << endl;
	  //cout << "PORT = " << c[1].as<int>() << endl;
	  count++;
	}
      timeval end;
      gettimeofday(&end,NULL);
      cout << "begin: " << begin.tv_sec << ":" << begin.tv_usec << endl;
      cout << "end: " << end.tv_sec << ":" << end.tv_usec << endl;
      cout << "count = " << count << endl;
      cout << "Operation done successfully" << endl;
      C.disconnect ();

   }catch (const std::exception &e){
      cerr << e.what() << std::endl;
      return 1;
   }
}
