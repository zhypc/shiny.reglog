check_namespace <- function(package) {
  if (!requireNamespace(package, quietly = T)) {
    stop(call. = F, 
         paste0("To use this functionality, you need to additionally install package: '",
                package,
                "'. You can do it by typing `install.packages('",
                package, "')`."))
  }
}

blank_textInputs <- function(inputs, session){
  for(input in inputs){
    
    updateTextInput(session,
                    inputId = input,
                    value = "")
    
  }
}

get_url_shiny <- function(session) {
  
  clientData <- reactiveValuesToList(session$clientData)
  
  path <- c()
  path <- paste(clientData$url_protocol,
                clientData$url_hostname,
                sep = "//")
  
  if (nchar(clientData$url_port) > 0)
    path <- paste(path, clientData$url_port, sep = ":")
  
  return(paste0(path, clientData$url_pathname))
  
}

modals_check_n_show <- function(private, modalname) {
  
  if (isTRUE(private$use_modals) || (is.list(private$use_modals) && !isFALSE(private$use_modals[[modalname]]))) {
    showModal(
      modalDialog(title = RegLog_txt(lang = private$lang, custom_txts = private$custom_txts, x = paste(modalname, "t", sep = "_")),
                  p(RegLog_txt(lang = private$lang, custom_txts = private$custom_txts, x = paste(modalname, "b", sep = "_"))),
                  footer = modalButton("OK"))
    )
  }
  
}

check_user_login <- function(x){
  nchar(x) >= 3 & nchar(x) <= 30
}

getRandomString <- function(n = 1) {
  a <- do.call(paste0, replicate(5, sample(letters, n, TRUE), FALSE))
  paste0(a, sprintf("%04d", sample(9999, n, TRUE)), sample(letters, n, TRUE))
}

check_user_pass <- function(x){
  nchar(x) >= 8 & nchar(x) <= 30
}

check_user_mail <- function(x) {
  stringi::stri_detect(regex = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z-a-z]{2,}$", str = as.character(x))
}

#' function to save message to logs
#' @param message reveived message
#' @param direction either received or sent
#' @param self R6 object
#' @param session shiny object
#' @param no_db boolean: if TRUE, then inhibits inputing into database. 
#' Defaults to FALSE
#' @noRd

save_to_logs <- function(message, direction, self, session, no_db = F) {

  # check options
  if (direction %in% c("sent", "received")) {
    log_save <- getOption("RegLogServer.logs", 1) >= 1
    log_input <- getOption("RegLogServer.logs_to_database", 0) >= 1
  } else if (direction == "shown") {
    log_save <- getOption("RegLogServer.logs", 1) >= 2
    log_input <- getOption("RegLogServer.logs_to_database", 0) >= 2
  }
  
  # if log is to be saved into self$log
  if (log_save) {
    self$log[[as.character(direction)]][[message$time]] <-
      data.frame(session = session$token,
                 type = as.character(message$type),
                 note = if(is.null(message$logcontent)) "" else as.character(message$logcontent))
  }
  
  # if log is to be input into the database
  if (log_input && isFALSE(no_db)) {
    if (!is.null(self$dbConnector)) {
          self$dbConnector$.__enclos_env__$private$input_log(
      message = message,
      direction = direction,
      session = session)
    }
  }
}

#' function to replace multiple values in string
#' @param x string to make replacements on
#' @param to_replace named list of character strings to replace
#' @noRd

string_interpolate <- function(x, to_replace) {
  
  look_for <- paste0("?", names(to_replace), "?")
  
  for (i in seq_along(look_for)) {
    if (!is.null(to_replace[[i]])) {
      x <- gsub(x = x, pattern = look_for[i], replacement = to_replace[[i]], fixed = T)
    }
  }
  
  return(x)
}

#' function to create standardized timestamp
#'
#' @export

db_timestamp <- function() {
  
  format(Sys.time(), format = "%Y-%m-%d %H:%M:%OS3")
  
}

getUserPermissions <- function(userId, conn){
  getUserPermissionsSql = 
    "SELECT permissions.id, studies.code, users.username FROM permissions
        INNER JOIN studies ON studies.id = permissions.study_id
        INNER JOIN users ON users.id = permissions.user_id
       WHERE user_id = ?user_id"
  getUserPermissionQuery = DBI::sqlInterpolate(conn, getUserPermissionsSql, user_id = userId)
  DBI::dbGetQuery(conn, getUserPermissionQuery)
}


getAllPermissions <- function(conn) {
  getPermissionsSql <- "SELECT permissions.id AS Id, users.username AS Username, studies.code AS Study FROM permissions 
                  INNER JOIN users ON users.id = permissions.user_id
                  INNER JOIN studies ON studies.id = permissions.study_id"
  DBI::dbGetQuery(conn, getPermissionsSql)
}

getUserIdFromUsername <- function(conn, username){
  getUserSql <- "SELECT id FROM users WHERE username = ?username"
  getUserQuery <- DBI::sqlInterpolate(conn, getUserSql, username = username)
  DBI::dbGetQuery(conn, getUserQuery)[[1]]
}

getStudyIdFromCode <- function(conn, code){
  getStudySql <- "SELECT id FROM studies WHERE code = ?code"
  getStudyQuery <- DBI::sqlInterpolate(conn, getStudySql, code = code)
  DBI::dbGetQuery(conn, getStudyQuery)[[1]]
}

getCompanyIdFromDescription <- function(conn, description) {
  getCompanySql <- "SELECT id from companies WHERE description = ?description"
  getCompanyQuery <- DBI::sqlInterpolate(conn, getCompanySql, description = description)
  DBI::dbGetQuery(conn, getCompanyQuery)[[1]]
}

getAllCompanies <- function(conn) {
  getCompaniesSql <- "SELECT code AS CompanyCode, description AS Company, id as CompanyID from companies"
  DBI::dbGetQuery(conn, getCompaniesSql)
}

getAllStudies <- function(conn) {
  getStudiesSql <- "SELECT studies.code AS StudyCode,
                    companies.description AS Company,
                    studies.description AS Long_name,
                    studies.drug_name as Trial_Drug,
                    studies.subjid_unique as Unique_Subjid,
                    studies.id AS StudyID
                    from studies INNER JOIN companies ON companies.id = studies.company_id"
  DBI::dbGetQuery(conn, getStudiesSql)
}