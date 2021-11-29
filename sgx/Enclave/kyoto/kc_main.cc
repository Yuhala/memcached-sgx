/*
 * Created on Mon Nov 29 2021
 *
 * Copyright (c) 2021 Peterson Yuhala, IIUN
 */

#include "kchashdb.h"
//#include "kcdirdb.h"
//#include "kctextdb.h"

#include "kyoto_logger_in.h"

using namespace std;
using namespace kyotocabinet;

//forward declarations
int kc_main();
void traverse_db();
int
    HashDB db;

// main routine

#ifndef USE_SGX
int main()
{
  return kc_main();
}
#endif

int kc_main()
{

  kc_set_bench(10);

  // create the database object
  int num_records = 10;

  printf(">>>>>>>>  kyoto hashdb test >>>>>>>>\n");

  // open the database
  if (!db.open("casket.kcd", HashDB::OWRITER | HashDB::OCREATE | HashDB::OAUTOSYNC))
  {
    //cerr << "open error: " << db.error().name() << endl;
    log_kyoto_info("open error", _KCCODELINE_);
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

  traverse_db();

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

void traverse_db()
{
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
}

/**
 * KC set benchmark: set numRecords for the thread with given id
 * Each thread will create and work w/ and independent database.
 */
void kc_set_bench(int numRecords, int tid)
{
  //create the db
  const char dbName[16];
  snprintf(dbName, 16, "kyotoDB_%d", tid);

  // open the database
  if (!db.open(dbName, HashDB::OWRITER | HashDB::OCREATE | HashDB::OAUTOSYNC))
  {
    //cerr << "open error: " << db.error().name() << endl;
    log_kyoto_info("open error", _KCCODELINE_);
  }

  //set the kv pairs
  for (int i = 0; i < numRecords; i++)
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

  //todo: close db
  //causes error but we just delete it afterwards so not a big deal
}