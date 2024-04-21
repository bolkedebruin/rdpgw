package database

type Database interface {
        GetPassword (username string) string
}