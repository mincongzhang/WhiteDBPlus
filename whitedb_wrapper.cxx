#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>

/* Include dbapi.h for WhiteDB API functions */
#include "dbapi.h"

#define log(msg) do{std::cout<<msg<<std::endl;}while(0)

const int KEY_FIELD = 0;
const int VAL_FIELD = 1;


//TODO: process/thread safe
//TODO: write our own wg_print_record so that to save result in a string
class WhiteDbKeyValueMap {
private:
  std::string m_db_name;
  void* m_db_ptr;

  bool checkValid() const {
    if(m_db_ptr){ return true; }

    log("ERROR: Failed to attach to database ["<<m_db_name<<"]");
    return false;
  }

  bool setString(void *rec, int field, std::string key) {
    wg_int enc = wg_encode_str(m_db_ptr, &key[0], NULL);
    if(enc==WG_ILLEGAL) {
      log("failed to encode an integer.");
      return false;
    }

    if(wg_set_field(m_db_ptr, rec, field, enc) < 0) {
      log("failed to store a field.");
      return false;
    }

    return true;
  }

  //NOTE:
  //Writing will be somewhat faster than with wg_set_field().
  //It is the responsibility of the caller to ensure that the field to be written really is one that contains no earlier data.
  bool setNewString(void *rec, int field, std::string key) {
    wg_int enc = wg_encode_str(m_db_ptr, &key[0], NULL);
    if(enc==WG_ILLEGAL) {
      log("failed to encode an integer.");
      return false;
    }

    if(wg_set_new_field(m_db_ptr, rec, field, enc) < 0) {
      log("failed to store a field.");
      return false;
    }

    return true;
  }

public:
  WhiteDbKeyValueMap(const std::string & db_name, const int db_size):m_db_name(db_name){
    //If the size parameter is > 0, the named shared memory segment exists and
    //it is smaller than the given size, the call returns NULL.
    //use wg_attach_existing_database() for existing db
    m_db_ptr = wg_attach_database(&m_db_name[0], db_size);
    checkValid();
  }

  ~WhiteDbKeyValueMap(){
    wg_detach_database(m_db_ptr);
  }

  bool get(std::string key, std::string & val) const {
    if(!checkValid()) return false;

    void * existing_rec = wg_find_record_str(m_db_ptr, KEY_FIELD, WG_COND_EQUAL, &key[0], NULL);
    if(existing_rec) {
      wg_int enc = wg_get_field(m_db_ptr, existing_rec, VAL_FIELD);
      char *str = wg_decode_str(m_db_ptr, enc);
      if(!str){
        log("ERROR: Got field but failed to decode");
        wg_print_record(m_db_ptr, (wg_int *) existing_rec);
        log("");
        return false;
      }

      val = str;
      return true;
    }

    log("ERROR: record with key ["<<key<<"] doesn't exist");
    return false;
  }

  bool create(std::string key, std::string val){
    if(!checkValid()) return false;

    //Check if already exists
    void * existing_rec = wg_find_record_str(m_db_ptr, KEY_FIELD, WG_COND_EQUAL, &key[0], NULL);
    if(existing_rec) {
      log("Key ["<<key<<"] already in DB:");
      wg_print_record(m_db_ptr, (wg_int *) existing_rec);
      log("");
      return false;
    }

    void *rec = wg_create_record(m_db_ptr, 2);
    if (rec==NULL) {
      log("rec creation error.");
      return false;
    }
    //TODO: write 2 fields in one time?
    return setNewString(rec,KEY_FIELD,key) && setNewString(rec,VAL_FIELD,val);
  }

  bool update(std::string key, std::string val){
    if(!checkValid()) return false;

    void * existing_rec = wg_find_record_str(m_db_ptr, KEY_FIELD, WG_COND_EQUAL, &key[0], NULL);
    if(existing_rec) {
      setString(existing_rec,VAL_FIELD,val);
      return true;
    }
    return false;
  }

  bool insert(std::string key, std::string val){
    if(!checkValid()) return false;

    //Try update first
    void * existing_rec = wg_find_record_str(m_db_ptr, KEY_FIELD, WG_COND_EQUAL, &key[0], NULL);
    if(existing_rec) {
      setString(existing_rec,VAL_FIELD,val);
      return true;
    }

    //Create new record
    void *rec = wg_create_record(m_db_ptr, 2);
    if (rec==NULL) {
      log("rec creation error.");
      return false;
    }
    //TODO: write 2 fields in one time?
    return setNewString(rec,KEY_FIELD,key) && setNewString(rec,VAL_FIELD,val);
  }

  bool remove(std::string key){
    if(!checkValid()) return false;

    void * existing_rec = wg_find_record_str(m_db_ptr, KEY_FIELD, WG_COND_EQUAL, &key[0], NULL);
    if(existing_rec) {
      return (wg_delete_record(m_db_ptr, existing_rec) == 0);
    }

    return false;
  }

  void dump() const {
    log("Dumping ["<<m_db_name<<"]:");
    wg_print_db(m_db_ptr);
  }

  bool deleteDB(){
    if(wg_delete_database(&m_db_name[0])==0){
      return true;
    }

    return false;
  }
};

template<typename T>
std::string toString ( T num ){
  std::stringstream ss; ss << num; return ss.str();
}

int main(int argc, char **argv) {
  WhiteDbKeyValueMap map("mizhang_whitedb",2000000);

  ///////////////////////////////////////////
  std::string key("isin"), val("123456678");
  log("CREATE:");
  if(map.insert(key,val)){
    log("created ["<<key<<"]->["<<val<<"]");
  }
  log("");

  ///////////////////////////////////////////
  log("CREATE SAME:");
  if(map.insert(key,val)){
    log("created ["<<key<<"]->["<<val<<"]");
  }
  log("");

  ///////////////////////////////////////////
  log("GET:");
  std::string get_val;
  if(map.get(key,get_val)){
    log("get ["<<key<<"]->["<<get_val<<"]");
  }
  log("");

  ///////////////////////////////////////////
  log("CREATE MANY:");
  for(int i=0; i<10;++i){
    std::string key = toString(i);
    std::string val = key+key;
    if(map.insert(key,val)){
      log("created ["<<key<<"]->["<<val<<"]");
    }
  }
  log("");

  ///////////////////////////////////////////
  log("UPDATE MANY:");
  for(int i=0; i<10;++i){
    std::string key = toString(i);
    std::string val = key+key+key;
    if(map.insert(key,val)){
      log("update ["<<key<<"]->["<<val<<"]");
    }
  }
  log("");

  ///////////////////////////////////////////
  log("DUMP:");
  map.dump();
  log("");

  ///////////////////////////////////////////
  log("REMOVE MANY:");
  for(int i=5; i<10;++i){
    std::string key = toString(i);
    if(map.remove(key)){
      log("remove ["<<key<<"]");
    }
  }
  log("");

  ///////////////////////////////////////////
  log("DUMP:");
  map.dump();
  log("");

  if(map.deleteDB()){
    log("db deleted successfully");
  }
}
