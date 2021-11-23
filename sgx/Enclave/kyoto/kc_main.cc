

#include "kchashdb.h"

#include "kyoto_logger_in.h"

using namespace std;
using namespace kyotocabinet;

//log_kyoto_error("",__func__);

// main routine
int kc_main()
{

  // create the database object
  HashDB db;

  printf(">>>>>>>>  kyoto hashdb test >>>>>>>>\n");

  // open the database
  if (!db.open("casket.kcd", HashDB::OWRITER | HashDB::OCREATE))
  {
    //cerr << "open error: " << db.error().name() << endl;
    log_kyoto_error("open error", db.error().name(), __func__);
  }

  // store records
  if (!db.set("foo", "hop") ||
      !db.set("bar", "step") ||
      !db.set("baz", "jump"))
  {
    //cerr << "set error: " << db.error().name() << endl;
    log_kyoto_error("set error", db.error().name(), __func__);
  }

  // retrieve a record
  string value;
  if (db.get("foo", &value))
  {
    //cout << value << endl;
    printf("Value is %s\n", value);
  }
  else
  {
    //cerr << "get error: " << db.error().name() << endl;
    log_kyoto_error("get error", db.error().name(), __func__);
  }

  // traverse records
  DB::Cursor *cur = db.cursor();
  cur->jump();
  string ckey, cvalue;
  while (cur->get(&ckey, &cvalue, true))
  {
    //cout << ckey << ":" << cvalue << endl;
    printf("Key: %s Value: %d", ckey, cvalue);
  }
  delete cur;

  // close the database
  if (!db.close())
  {
    //cerr << "close error: " << db.error().name() << endl;
    log_kyoto_error("close error", db.error().name(), __func__);
  }

  return 0;
}
