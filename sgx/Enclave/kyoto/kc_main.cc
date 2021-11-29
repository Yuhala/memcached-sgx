

#include "kchashdb.h"
//#include "kcdirdb.h"

#include "kyoto_logger_in.h"

using namespace std;
using namespace kyotocabinet;

//forward declarations
int kc_main();

// main routine

#ifndef USE_SGX
int main()
{
  return kc_main();
}
#endif

int kc_main()
{
  // create the database object
  HashDB db;

  printf(">>>>>>>>  kyoto hashdb test >>>>>>>>\n");

  // open the database
  if (!db.open("casket.kcd", HashDB::OWRITER | HashDB::OCREATE))
  {
    //cerr << "open error: " << db.error().name() << endl;
    log_kyoto_info("open error", _KCCODELINE_);
  }

  // store records
  if (!db.set("foo", "hop") ||
      !db.set("bar", "step") ||
      !db.set("baz", "jump"))
  {
    //cerr << "set error: " << db.error().name() << endl;
    log_kyoto_info("set error", _KCCODELINE_);
  }

  // retrieve a record
  string value;
  if (db.get("foo", &value))
  {

#ifdef USE_SGX
    printf("Value is: ?? TODO\n");
#else
    cout << value << endl;
#endif
  }
  else
  {

#ifdef USE_SGX
    log_kyoto_info("record get error", _KCCODELINE_);
#else
    cerr << "get error: " << db.error().name() << endl;
#endif
  }

  // traverse records
  DB::Cursor *cur = db.cursor();
  cur->jump();
  string ckey, cvalue;
  while (cur->get(&ckey, &cvalue, true))
  {

#ifdef USE_SGX
    printf("cannot traverse records well in sgx atm, TODO :-)\n");
#else
    cout << ckey << ":" << cvalue << endl;
#endif
  }
  delete cur;

  // close the database
  if (!db.close())
  {

#ifdef USE_SGX
    log_kyoto_info("close error", _KCCODELINE_);
#else
    cerr << "close error: " << db.error().name() << endl;
#endif
  }

  return 0;
}
