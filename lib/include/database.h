/**************************************************************************
 * database.h
 *
 *  Create on: 21/06/2019
 *
 *  Header for databas access for sqlite3
 *
 * Copyrights, 2019
 *
 **************************************************************************/
#ifndef __DATABASE_H__
#define __DATABASE_H__

/**************************************************************************
 * INCLUDES
 **************************************************************************/
#include <jansson.h>
#ifndef __USE_XOPEN
  #define __USE_XOPEN
#endif
#include <time.h>
#include <pthread.h>
#include <orcania.h>

/**************************************************************************
 * DEFINITIONS
 **************************************************************************/

#define DATABASE_COL_TYPE_INT    0
#define DATABASE_COL_TYPE_DOUBLE 1
#define DATABASE_COL_TYPE_TEXT   2
#define DATABASE_COL_TYPE_DATE   3
#define DATABASE_COL_TYPE_BLOB   4
#define DATABASE_COL_TYPE_BOOL   5
#define DATABASE_COL_TYPE_NULL   5

#define DATABASE_OK                0  /* No error */
#define DATABASE_ERROR             1  /* Generic error */
#define DATABASE_ERROR_PARAMS      2  /* Error in input parameters */
#define DATABASE_ERROR_CONNECTION  3  /* Error in database connection */
#define DATABASE_ERROR_QUERY       4  /* Error executing query */
#define DATABASE_ERROR_MEMORY      99 /* Error allocating memory */

#define DATABASE_OPTION_NONE   0x0000 /* Nothing whatsoever */
#define DATABASE_OPTION_SELECT 0x0001 /* Execute a SELECT statement */
#define DATABASE_OPTION_EXEC   0x0010 /* Execute an INSERT, UPDATE or DELETE statement */

/**
 * handle container
 */
struct _db_connection {
  int type;
  void * connection;
};

/**
 * sql value integer type
 */
struct _db_type_int {
  int value;
};

/**
 * sql value double type
 */
struct _db_type_double {
  double value;
};

/**
 * sql value date/time type
 */
struct _db_type_datetime {
  struct tm value;
};

/**
 * sql value string type
 */
struct _db_type_text {
  size_t length;
  char * value;
};

/**
 * sql value blob type
 */
struct _db_type_blob {
  size_t length;
  void * value;
};

/**
 * sql data container
 */
struct _db_data {
  int type;
  void * t_data;
};

/**
 * sql result structure
 */
struct _db_result {
  unsigned int nb_rows;
  unsigned int nb_columns;
  struct _db_data ** data;
};

/**
 * Close a database connection
 * return DATABASE_OK on success
 */
int db_close_db(struct _db_connection * conn);

/**
 * free data allocated by database functions
 */
void db_free(void * data);

/**
 * db_escape_string
 * Escapes a string
 * returned value must be free'd after use
 */
char * db_escape_string(const struct _db_connection * conn, const char * unsafe);

/**
 * db_execute_query
 * Execute a query, set the result structure with the returned values if available
 * if result is NULL, the query is executed but no value will be returned
 * options available
 * DATABASE_OPTION_NONE (0): no option
 * DATABASE_OPTION_SELECT: Execute a prepare statement (sqlite only)
 * DATABASE_OPTION_EXEC: Execute an exec statement (sqlite only)
 * return DATABASE_OK on success
 */
int db_execute_query(const struct _db_connection * conn, const char * query, struct _db_result * result, int options);

/**
 * db_query_insert
 * Execute an insert query
 * return DATABASE_OK on success
 */
int db_query_insert(const struct _db_connection * conn, const char * query);

/**
 * db_query_last_insert_id
 * return the id of the last inserted value
 * return a pointer to `struct _db_data *` on success, NULL otherwise.
 */
struct _db_data * db_query_last_insert_id(const struct _db_connection * conn);

/**
 * db_query_update
 * Execute an update query
 * return DATABASE_OK on success
 */
int db_query_update(const struct _db_connection * conn, const char * query);

/**
 * db_query_delete
 * Execute an delete query
 * return DATABASE_OK on success
 */
int db_query_delete(const struct _db_connection * conn, const char * query);

/**
 * db_query_select
 * Execute a select query, set the result structure with the returned values
 * return DATABASE_OK on success
 */
int db_query_select(const struct _db_connection * conn, const char * query, struct _db_result * result);

/**
 * db_execute_query_json
 * Execute a query, set the returned values in the json result
 * return DATABASE_OK on success
 */
int db_execute_query_json(const struct _db_connection * conn, const char * query, json_t ** j_result);

/**
 * db_query_select_json
 * Execute a select query, set the returned values in the json results
 * return DATABASE_OK on success
 */
int db_query_select_json(const struct _db_connection * conn, const char * query, json_t ** j_result);

/**
 * json queries
 * The following functions run a sql query based on a json_t * object for input parameters
 * The input parameter is called j_query
 * If the j_query is well-formed, the query is executed and if available and specified, the result is stored into the j_result object. j_result must be decref'd after use
 * Also, the sql query generated is stored into generated_query if specified, generated_query must be free'd after use
 * The query execution result is returned by the function
 * 
 * A j_query has the following form
 * {
 *   "table": "table_name"             // String, mandatory, the table name where the query is executed
 *   "columns": ["col1", "col2"]       // Array of strings, available for db_select, optional. If not specified,will be used
 *   "order_by": "col_name [asc|desc]" // String, available for db_select, specify the order by clause, optional
 *   "limit": integer_value            // Integer, available for db_select, specify the limit value, optional
 *   "offset"                          // Integer, available for db_select, specify the limit value, optional but available only if limit is set
 *   "values": [{                      // json object or json array of json objects, available for db_insert, mandatory, specify the values to update
 *     "col1": "value1",               // Generates col1='value1' for an update query
 *     "col2": value_integer,          // Generates col2=value_integer for an update query
 *     "col3", "value3",               // Generates col3='value3' for an update query
 *     "col4", null                    // Generates col4=NULL for an update query
 *   }]
 *   "set": {                          // json object, available for db_update, mandatory, specify the values to update
 *     "col1": "value1",               // Generates col1='value1' for an update query
 *     "col2": value_integer,          // Generates col2=value_integer for an update query
 *     "col3", "value3",               // Generates col3='value3' for an update query
 *     "col4", null                    // Generates col4=NULL for an update query
 *   }
 *   "where": {                        // json object, available for db_select, db_update and db_delete, mandatory, specify the where clause. All clauses are separated with an AND operator
 *     "col1": "value1",               // Generates col1='value1'
 *     "col2": value_integer,          // Generates col2=value_integer
 *     "col3": null,                   // Generates col3=NULL
 *     "col4", {                       // Generates col4<12
 *       "operator": "<",
 *       "value": 12
 *     },
 *     "col5", {                       // Generates col5 IS NOT NULL
 *       "operator": "NOT NULL"
 *     },
 *     "col6", {                       // Generates col6 LIKE '%value6%'
 *       "operator": "raw",
 *       "value": "LIKE '%value6%'"
 *     }
 *   }
 * }
 */

/**
 * db_select
 * Execute a select query
 * Uses a json_t * parameter for the query parameters
 * Store the result of the query in j_result if specified. j_result must be decref'd after use
 * Duplicate the generated query in generated_query if specified, must be free'd after use
 * return DATABASE_OK on success
 */
int db_select(const struct _db_connection * conn, const json_t * j_query, json_t ** j_result, char ** generated_query);

/**
 * db_insert
 * Execute an insert query
 * Uses a json_t * parameter for the query parameters
 * Duplicate the generated query in generated_query if specified, must be free'd after use
 * return DATABASE_OK on success
 */
int db_insert(const struct _db_connection * conn, const json_t * j_query, char ** generated_query);

/**
 * db_last_insert_id
 * return the id of the last inserted value
 * return a pointer to `json_t *` on success, NULL otherwise.
 * The returned value is of type JSON_INTEGER
 */
json_t * db_last_insert_id(const struct _db_connection * conn);

/**
 * db_update
 * Execute an update query
 * Uses a json_t * parameter for the query parameters
 * Duplicate the generated query in generated_query if specified, must be free'd after use
 * return DATABASE_OK on success
 */
int db_update(const struct _db_connection * conn, const json_t * j_query, char ** generated_query);

/**
 * db_delete
 * Execute a delete query
 * Uses a json_t * parameter for the query parameters
 * Duplicate the generated query in generated_query if specified, must be free'd after use
 * return DATABASE_OK on success
 */
int db_delete(const struct _db_connection * conn, const json_t * j_query, char ** generated_query);

/**
 * db_clean_result
 * Free all the memory allocated by the struct _db_result
 * return DATABASE_OK on success
 */
int db_clean_result(struct _db_result * result);

/**
 * db_clean_data
 * Free memory allocated by the struct _db_data
 * return DATABASE_OK on success
 */
int db_clean_data(struct _db_data * data);

/**
 * db_clean_data_full
 * Free memory allocated by the struct _db_data and the struct _db_data pointer
 * return DATABASE_OK on success
 */
int db_clean_data_full(struct _db_data * data);

/**
 * db_clean_connection
 * free memory allocated by the struct _db_connection
 * return DATABASE_OK on success
 */
int db_clean_connection(struct _db_connection * conn);

void getDbResult(struct _db_result result, int numColumn, void *pParamValue);

/**
 * db_connect_sqlite
 * Opens a database connection to a sqlite3 db file
 * return pointer to a struct _db_connection * on sucess, NULL on error
 */
struct _db_connection * db_connect_sqlite(const char * db_path);

/**
 * close a sqlite3 connection
 */
void db_close_sqlite(struct _db_connection * conn);

/**
 * escape a string
 * returned value must be free'd after use
 */
char * db_escape_string_sqlite(const struct _db_connection * conn, const char * unsafe);

/**
 * Return the id of the last inserted value
 */
int db_last_insert_id_sqlite(const struct _db_connection * conn);

/**
 * db_select_query_sqlite
 * Execute a select query on a sqlite connection, set the result structure with the returned values
 * Should not be executed by the user because all parameters are supposed to be correct
 * if result is NULL, the query is executed but no value will be returned
 * Useful for SELECT statements
 * return DATABASE_OK on success
 */
int db_select_query_sqlite(const struct _db_connection * conn, const char * query, struct _db_result * result);

/**
 * db_exec_query_sqlite
 * Execute a query on a sqlite connection
 * Should not be executed by the user because all parameters are supposed to be correct
 * No result is returned, useful for single INSERT, UPDATE or DELETE statements
 * return DATABASE_OK on success
 */
int db_exec_query_sqlite(const struct _db_connection * conn, const char * query);

/**
 * db_execute_query_json_sqlite
 * Execute a query on a sqlite connection, set the returned values in the json result
 * Should not be executed by the user because all parameters are supposed to be correct
 * return DATABASE_OK on success
 */
int db_execute_query_json_sqlite(const struct _db_connection * conn, const char * query, json_t ** j_result);

#endif
