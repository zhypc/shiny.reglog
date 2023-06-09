DBI_get_all_permissions_handler <- function(self, private, message){
  
  check_namespace("DBI")
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  getCompaniesSql <- "SELECT * FROM companies"
  getStudiesSql <- "SELECT * FROM studies"
  getUsersSql <- "SELECT * FROM users"
  allCompanies <- DBI::dbGetQuery(private$db_conn, getCompaniesSql)
  allStudies <- DBI::dbGetQuery(private$db_conn, getStudiesSql)
  allUsers <- DBI::dbGetQuery(private$db_conn, getUsersSql)
  
  allPermissions <- getAllPermissions(private$db_conn)
  
  RegLogConnectorMessage(
    "getAllPermissions", success = TRUE, 
    all_permissions = allPermissions,
    all_companies = allCompanies,
    all_studies = allStudies,
    all_users = allUsers
  )
}

DBI_adjust_permissions_handler <- function(self, private, message){
  
  check_namespace("DBI")
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  #set up the 'message to return' ahead of time so we don't need to repeat this code later
  messageToReturn <- RegLogConnectorMessage(
    message$type,
    success = TRUE,
    action = message$data$action,
    logcontent = paste0(message$data$action, " permissions for user: ", 
                        message$data$username, "/",
                        message$data$email, 
                        " to study: ", message$data$study,
                        " succeeded")
  )

  if(message$data$action == "Grant"){
    
    userId <- getUserIdFromUsername(private$db_conn, message$data$username)
    
    studyId <- getStudyIdFromCode(private$db_conn, message$data$study)
    
    permissionInsertSql <- paste0("INSERT INTO permissions",
                                  " (user_id, study_id, create_time, update_time)",
                                  " VALUES (?user_id, ?study_id, ?create_time, ?create_time)")
    
    permissionInsertStatement <- DBI::sqlInterpolate(private$db_conn, permissionInsertSql,
                                                              user_id = userId,
                                                              study_id = studyId,
                                                              create_time = db_timestamp())
    
    tryCatch({
      DBI::dbExecute(private$db_conn, permissionInsertStatement)
     }, 
     error = function(error){
       # need the <<- because changing variables in the outer scope do not "stick" here inside the catch (For some reason changes do stick in the try).
       messageToReturn$data$success <<- FALSE
       messageToReturn$logcontent <<- paste0("Granting permissions failed for user: ", 
                                            message$data$username, "/",
                                            message$data$email, ": ",
                                            " Action: ", message$data$action,
                                            " Study: ", message$data$study,
                                            " Error: ", paste(error, collapse = ";"))
     })
  } else if(message$data$action == "Revoke"){
    userId <- getUserIdFromUsername(private$db_conn, message$data$username)
    
    studyId <- getStudyIdFromCode(private$db_conn, message$data$study)
    
    permissionRemoveSql <- "DELETE FROM permissions WHERE user_id = ?user_id AND study_id = ?study_id"
    
    
    permissionRemoveStatement <- DBI::sqlInterpolate(private$db_conn, permissionRemoveSql,
                                                     user_id = userId,
                                                     study_id = studyId)
    tryCatch({
      DBI::dbExecute(private$db_conn, permissionRemoveStatement)
    }, 
    error = function(error){
      # need the <<- because changing variables in the outer scope do not "stick" here inside the catch (For some reason changes do stick in the try).
      messageToReturn$data$success <<- FALSE
      messageToReturn$logcontent <<- paste0("Revoking permissions failed for user: ", 
                                           message$data$username, "/",
                                           message$data$email, ": ",
                                           " Action: ", message$data$action,
                                           " Study: ", message$data$study,
                                           " Error: ", paste(error, collapse = ";"))
    })
  }

  messageToReturn$data$all_permissions <- getAllPermissions(private$db_conn)
  return(messageToReturn)
}

DBI_login_with_microsoft_handler <- function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  getSql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE email = ?email;")
  getQuery <- DBI::sqlInterpolate(private$db_conn, getSql, email = tolower(message$data$email))
  
  user_data <- DBI::dbGetQuery(private$db_conn, getQuery)
  
  if (nrow(user_data) == 0) {
    #if return no rows, then this is a new user; create an account for him.
    
    insertSql <- paste0("INSERT INTO ", private$db_tables[1],
                  " (username, password, email, create_time, update_time)",
                  " VALUES (?username, ?password, ?email, ?create_time, ?create_time)")
    insertQuery <- DBI::sqlInterpolate(private$db_conn, insertSql, 
                                 username = message$data$email, # username will just be their email
                                 password = scrypt::hashPassword(getRandomString()), # create a random password that they can reset later if they want to log in through the normal, non-Microsoft way
                                 email = tolower(message$data$email),
                                 create_time = db_timestamp())
    
    DBI::dbExecute(private$db_conn, insertQuery)
    
    # after creating the user get user data.
    user_data <- DBI::dbGetQuery(private$db_conn, getQuery)
  }
    # always successfully login since they have already authenticated with Microsoft
  
    permissions <- getUserPermissions(user_data$id, private$db_conn)

    # return login success message so that RegLogServer_listener will handle the login process (see line 68 where it receives the message)
    RegLogConnectorMessage(
      "login", success = TRUE, username = TRUE, password = TRUE, is_logged_microsoft = TRUE,
      permissions = permissions,
      user_id = user_data$username,
      user_mail = tolower(user_data$email),
      account_id = user_data$id,
      logcontent = paste(message$data$username, "logged in with Microsoft")
    )
}

#' DBI login handler
#' 
#' @description Default handler function querying database to confirm login 
#' procedure. Used within object of `RegLogDBIConnector` class internally.
#' 
#' @param self R6 object element
#' @param private R6 object element
#' @param message RegLogConnectorMessage which should contain within its data:
#' - username
#' - password
#' @family DBI handler functions
#' @concept DBI_handler
#' @keywords internal

DBI_login_handler <- function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  sql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE username = ?username;")
  query <- DBI::sqlInterpolate(private$db_conn, sql, username = message$data$username)
  
  user_data <- DBI::dbGetQuery(private$db_conn, query)
  
  # check condition and create output message accordingly
  
  if (nrow(user_data) == 0) {
    # if don't return any, then nothing happened
    
    RegLogConnectorMessage(
      "login", success = FALSE, username = FALSE, password = FALSE,
      logcontent = paste(message$data$username, "don't exist")
    )
    
  } else {
    # if there is a row present, check password
    
    if (scrypt::verifyPassword(user_data$password, message$data$password)) {
      # if success: user logged in
      
      permissions <- getUserPermissions(user_data$id, private$db_conn)
      
      RegLogConnectorMessage(
        "login", success = TRUE, username = TRUE, password = TRUE, is_logged_microsoft = TRUE,
        user_id = user_data$username,
        user_mail = tolower(user_data$email),
        account_id = user_data$id,
        permissions = permissions,
        logcontent = paste(message$data$username, "logged in")
      )
      
    } else {
      # if else: the password didn't match
      
      RegLogConnectorMessage(
        "login", success = FALSE, username = TRUE, password = FALSE,
        logcontent = paste(message$data$username, "bad pass")
      )
    }
  }
}

#' DBI register handler
#' 
#' @description Default handler function querying database to confirm registration 
#' validity and input new data. Used within object of `RegLogDBIConnector` class internally.
#' 
#' @param self R6 object element
#' @param private R6 object element
#' @param message RegLogConnectorMessage which should contain within its data:
#' - username
#' - password
#' - email
#' @family DBI handler functions
#' @concept DBI_handler
#' @keywords internal

DBI_register_handler = function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  # firstly check if user or email exists
  sql <- paste0("SELECT * FROM ", private$db_tables[1], 
                " WHERE username = ?username OR email = ?email;")
  query <- DBI::sqlInterpolate(private$db_conn, sql, 
                               username = message$data$username, 
                               email = tolower(message$data$email))
  
  user_data <- DBI::dbGetQuery(private$db_conn, query)
  
  if (nrow(user_data) > 0) {
    # if query returns data don't register new
    message_to_send <- RegLogConnectorMessage(
      "register", 
      success = FALSE, 
      username = !message$data$username %in% user_data$username,
      email = !message$data$email %in% user_data$email)
    
    if (!message_to_send$data$username && !message_to_send$data$email) {
      message_to_send$logcontent <- paste0(message$data$username, "/", message$data$email, " conflict")
    } else if (!message_to_send$data$username) {
      message_to_send$logcontent <- paste(message$data$username, "conflict")
    } else if (!message_to_send$data$email) {
      message_to_send$logcontent <- paste(message$data$email, "conflict")
    }
    
    return(message_to_send)
    
  } else {
    # if query returns no data register new
    sql <- paste0("INSERT INTO ", private$db_tables[1], 
                  " (username, password, email, create_time, update_time)",
                  " VALUES (?username, ?password, ?email, ?create_time, ?create_time)")
    query <- DBI::sqlInterpolate(private$db_conn, sql, 
                                 username = message$data$username, 
                                 password = scrypt::hashPassword(message$data$password),
                                 email = tolower(message$data$email),
                                 create_time = db_timestamp())
    
    DBI::dbExecute(private$db_conn, query)
    
    return(
      RegLogConnectorMessage(
        "register", 
        success = TRUE, username = TRUE, email = TRUE,
        user_id = message$data$username,
        user_mail = tolower(message$data$email),
        password = message$data$password,
        logcontent = paste(message$data$username, message$data$email, sep = "/")
      )
    )
  }
}

#' DBI edit to the database handler
#' 
#' @description Default handler function querying database to confirm credentials
#' edit procedure and update values saved within database. Used within object of 
#' `RegLogDBIConnector` class internally.
#' @param self R6 object element
#' @param private R6 object element
#' @param message RegLogConnectorMessage which need to contain within its data:
#' - account_id
#' - password
#' 
#' It can also contain elements for change:
#' - new_username
#' - new_email
#' - new_password
#' @family DBI handler functions
#' @concept DBI_handler
#' @keywords internal

DBI_credsEdit_handler <- function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  # firstly check login credentials
  
  sql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE id = ?id;")
  query <- DBI::sqlInterpolate(private$db_conn, sql, id = message$data$account_id)
  
  user_data <- DBI::dbGetQuery(private$db_conn, query)

  # check password
    
  if (isFALSE(scrypt::verifyPassword(user_data$password, message$data$password))) {
    # if FALSE: don't allow changes
    
    message_to_send <- RegLogConnectorMessage(
      "credsEdit", success = FALSE, password = FALSE,
      logcontent = paste(user_data$username, "bad pass")
    )
    
  } else {
    # if TRUE: allow changes
    
    ## Additional checks: if unique values (username, email) that are to be changed
    ## are already present in the database
    
    # firsty parse veryfifying SQL query correctly
    verify <- ""
    
    if (!is.null(message$data$new_username)) {
      verify <- paste(verify ,"username = ?username", sep = if (nchar(verify) == 0) " " else " OR ")
    }
    if (!is.null(message$data$new_email)) {
      verify <- paste(verify, "email = ?email", sep = if (nchar(verify) == 0) " " else " OR ")
    }
    
    # if there is anything to verify...
    if (nchar(verify) > 0) {
      
      sql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE ", verify, ";")
      
      # interpolate correct fields for check
      if (!is.null(message$data$new_username) && !is.null(message$data$new_email)) {
        query <- DBI::sqlInterpolate(private$db_conn, sql, 
                                     username = message$data$new_username,
                                     email = tolower(message$data$new_email))
      } else if (!is.null(message$data$new_username)) {
        query <- DBI::sqlInterpolate(private$db_conn, sql, 
                                     username = message$data$new_username)
      } else if (!is.null(message$data$new_email)) {
        query <- DBI::sqlInterpolate(private$db_conn, sql,
                                     email = tolower(message$data$new_email))
      }
      user_data <- DBI::dbGetQuery(private$db_conn, query)
    }
    
    # if something is returned, send fail back
    if (nchar(verify) > 0 && nrow(user_data) > 0) {
      
      message_to_send <- RegLogConnectorMessage(
        "credsEdit", success = FALSE,
        password = TRUE,
        # if there is a conflict, these returns FALSE
        new_username = !isTRUE(message$data$new_username %in% user_data$username),
        new_email = !isTRUE(message$data$new_email %in% user_data$email))
      
      message_to_send$logcontent <-
        paste0(user_data$username, " conflict:",
               if (!message_to_send$data$new_username) paste(" username:", message$data$new_username),
               if (!message_to_send$data$new_email) paste(" email:", message$data$new_email), "." )
      
    } else {
      # if nothing is returned, update can be made!
      update_query <- paste("UPDATE", private$db_tables[1], "SET update_time = ?update_time")
      interpolate_vals <- list("update_time" = db_timestamp())
      # for every field to update popupalte query and interpolate vals
      if (!is.null(message$data$new_username)) {
        update_query <- paste(update_query, "username = ?username", sep = ", ")
        interpolate_vals[["username"]] <- message$data$new_username
      }
      if (!is.null(message$data$new_password)) {
        update_query <- paste(update_query, "password = ?password", sep = ", ")
        interpolate_vals[["password"]] <- scrypt::hashPassword(message$data$new_password)
      }
      if (!is.null(message$data$new_email)) {
        update_query <- paste(update_query, "email = ?email", sep = ", ")
        interpolate_vals[["email"]] <- tolower(message$data$new_email)
      }
      update_query <- paste(update_query, "WHERE id = ?account_id;")
      interpolate_vals[["account_id"]] <- message$data$account_id
      
      query <- DBI::sqlInterpolate(private$db_conn, update_query,
                                   .dots = interpolate_vals)
      
      DBI::dbExecute(private$db_conn, query)
      
      message_to_send <- RegLogConnectorMessage(
        "credsEdit", success = TRUE,
        password = TRUE,
        new_user_id = message$data$new_username,
        new_user_mail = tolower(message$data$new_email),
        new_user_pass = if(!is.null(message$data$new_password)) TRUE else NULL)
      
      info_to_log <- 
        c(message_to_send$data$new_user_id,
          message_to_send$data$new_user_mail,
          if (!is.null(message_to_send$new_user_pass)) "pass_change")
      
      message_to_send$logcontent <-
        paste(user_data$username, "updated",
              paste(info_to_log,
                    collapse = "/")
        )
    }
  }
  return(message_to_send)
}


#' DBI resetpass code generation handler
#' 
#' @description Default handler function querying database to confirm credentials
#' edit procedure and update values saved within database. Used within object of 
#' `RegLogDBIConnector` class internally.
#' @param self R6 object element
#' @param private R6 object element
#' @param message RegLogConnectorMessage which need to contain within its data:
#' - username
#' 
#' @family DBI handler functions
#' @concept DBI_handler
#' @keywords internal

DBI_resetPass_generation_handler <- function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  sql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE username = ?;")
  query <- DBI::sqlInterpolate(private$db_conn, sql, message$data$username)
  
  user_data <- DBI::dbGetQuery(private$db_conn, query)
  
  # check condition and create output message accordingly
  
  if (nrow(user_data) == 0) {
    # if don't return any, then nothing happened
    
    message_to_send <- RegLogConnectorMessage(
      "resetPass_generate", success = FALSE, 
      logcontent = paste(message$data$username, "don't exist")
    )
    
    # if username exists, generate new resetpass code
  } else {
    
    reset_code <- paste(floor(stats::runif(10, min = 0, max = 9.9)), collapse = "")
    
    sql <- paste0("INSERT INTO ", private$db_tables[2], 
                  " (user_id, reset_code, used, create_time, update_time)",
                  " VALUES (?user_id, ?reset_code, 0, ?create_time, ?create_time)")
    query <- DBI::sqlInterpolate(private$db_conn, sql, 
                                 user_id = user_data$id,
                                 reset_code = reset_code,
                                 create_time = db_timestamp())

    DBI::dbExecute(private$db_conn, query)
    
    message_to_send <- RegLogConnectorMessage(
      "resetPass_generate", success = TRUE,  
      user_id = message$data$username,
      user_mail = tolower(user_data$email),
      reset_code = reset_code,
      logcontent = paste(message$data$username, "code generated")
    )
  }
  return(message_to_send)
  
}

#' DBI resetpass code confirmation handler
#' 
#' @description Default handler function querying database to confirm credentials
#' edit procedure and update values saved within database. Used within object of 
#' `RegLogDBIConnector` class internally.
#' @param self R6 object element
#' @param private R6 object element
#' @param message RegLogConnectorMessage which need to contain within its data:
#' - username
#' - reset_code
#' - password
#' 
#' @family DBI handler functions
#' @concept DBI_handler
#' @keywords internal

DBI_resetPass_confirmation_handler <- function(self, private, message) {
  
  check_namespace("DBI")
  
  private$db_check_n_refresh()
  on.exit(private$db_disconnect())
  
  sql <- paste0("SELECT * FROM ", private$db_tables[1], " WHERE username = ?;")
  query <- DBI::sqlInterpolate(private$db_conn, sql, message$data$username)
  
  user_data <- DBI::dbGetQuery(private$db_conn, query)
  
  # check condition and create output message accordingly
  
  if (nrow(user_data) == 0) {
    # if don't return any, then nothing happened
    
    message_to_send <- RegLogConnectorMessage(
      "resetPass_confirm", success = FALSE, username = FALSE, code_valid = FALSE,
      logcontent = paste(message$data$username, "don't exist")
    )
    
    # if username exists, check for the resetcode
  } else {
    
    sql <- paste0("SELECT * FROM ", private$db_tables[2], 
                  # matching reset code is found for this user_id
                  " WHERE user_id = ?user_id AND reset_code = ?reset_code",
                  # reset code is not used already
                  " AND used = 0;")
    
    query <- DBI::sqlInterpolate(private$db_conn, sql,
                                 user_id = user_data$id,
                                 reset_code = message$data$reset_code)
    
    reset_code_data <- DBI::dbGetQuery(private$db_conn, query)
    
    not_expired <- 
      (lubridate::as_datetime(reset_code_data$create_time) + lubridate::period(4, "hours")) > Sys.time()
    
    # if not used reset code matches and isn't expired, update the database
    if (nrow(reset_code_data) > 0 && not_expired) {
      
      # update user data
      sql <- paste0("UPDATE ", private$db_tables[1],
                    " SET password = ?password, update_time = ?update_time WHERE id = ?user_id")
      
      query <- DBI::sqlInterpolate(private$db_conn, sql,
                                   password = scrypt::hashPassword(message$data$password),
                                   update_time = db_timestamp(),
                                   user_id = user_data$id[1])
      
      DBI::dbExecute(private$db_conn, query)
      
      # update reset_code
      sql <- paste0("UPDATE ", private$db_tables[2],
                    " SET used = 1, update_time = ?update_time WHERE id = ?reset_code_id")
      
      query <- DBI::sqlInterpolate(private$db_conn, sql,
                                   update_time = db_timestamp(),
                                   reset_code_id = reset_code_data$id[1])

      DBI::dbExecute(private$db_conn, query)
      
      message_to_send <- RegLogConnectorMessage(
        "resetPass_confirm", success = TRUE, username = TRUE, code_valid = TRUE,
        logcontent = paste(message$data$username, "changed")
      )
      # if reset code wasn't valid
    } else {
      
      message_to_send <- RegLogConnectorMessage(
        "resetPass_confirm", success = FALSE, username = TRUE, code_valid = FALSE,
        logcontent = paste(message$data$username, "invalid code")
      )
    }
  }
  
  return(message_to_send)
  
}
