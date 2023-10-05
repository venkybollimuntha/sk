value = input("Please Scan the Barcode:: ")

import mysql.connector

# Define the database connection parameters
config = {
    "host": "",       # Replace with your MySQL server hostname
    "user": "admin",   # Replace with your MySQL username
    "password": "",  # Replace with your MySQL password
    "database": ""  # Replace with the name of your MySQL database
}

# Create a MySQL database connection
try:
    connection = mysql.connector.connect(**config)

    if connection.is_connected():
        print(f"Fetching results for {value}")

        cursor = connection.cursor(dictionary=True)
        query = f"SELECT * FROM member_data_admin WHERE MemberID = '{value}'"

        # Execute the query
        cursor.execute(query)

        # Fetch the results
        result = cursor.fetchone()

        if result:

            print("********************************")

            print("Membership ID:: ",result['MemberID'])
            print("Member Name:: ",result['Name'])
            print("Phone:: ",result['Phone'])
            print("Membership type:: ",result['Membership'])
            print("Membership date:: ",result['Enrolled Date'])
            print("Membership Expiry:: ",result['Membership Expiry'])

            print("********************************")


        else:
            print("No data found for the specified primary key.")

    # Perform database operations here
    # For example, execute SQL queries, fetch data, etc.

except mysql.connector.Error as e:
    print("Error connecting to MySQL database:", e)

finally:
    if connection.is_connected():
        connection.close()
