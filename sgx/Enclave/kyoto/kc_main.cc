

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

  int num_records = 10;

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

  for (int i = 0; i < num_records; i++)
  {
    const char value[16];
    const char key[16];
    snprintf(key, 16, "kyoto_key_%d", i);
    snprintf(value, 16, "kyoto_value_%d", i);
    if (!db.set(key, value))
    {
      log_kyoto_info("set error", _KCCODELINE_);
    }
  }

  // retrieve a record
  string value;
  if (db.get("foo", &value))
  {

#ifdef USE_SGX
    printf("Value of foo is: %s\n", value);
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
    //printf("cannot traverse records well in sgx atm, TODO :-)\n");
    printf("Key %s: Value: %s\n", ckey, cvalue);
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
