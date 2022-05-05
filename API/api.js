let express = require("express");
let app = express();
require("dotenv").config();
let port = 3004;
let md5 = require("md5");
let sqlite3 = require("sqlite3").verbose();
let cors = require("cors");
let jwt = require("jsonwebtoken");
let bcrypt = require("bcryptjs");
let DBSOURCE = "usersdb.sqlite";
let { verifyTokenAdmin, verifyTokenCustomer } = require("./middleware");

let db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    // Cannot open database
    console.error(err.message);
    throw err;
  } else {
    let salt = bcrypt.genSaltSync(10);

    db.run(
      `CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username text, 
            Email text, 
            Password text,             
            Salt text,    
            Token text,
            Admin integer,
            DateLoggedIn DATE,
            DateCreated DATE
            )`,
      (err) => {
        if (err) {
          // Table already created
          console.log("Table already created");
        } else {
          // Table just created, creating some rows
          let insert =
            "INSERT INTO Users (Username, Email, Password, Salt, DateCreated, Admin) VALUES (?,?,?,?,?,?)";
          db.run(insert, [
            "user1",
            "user1@example.com",
            bcrypt.hashSync("user1", salt),
            salt,
            Date("now"),
            0,
          ]);
          db.run(insert, [
            "user2",
            "user2@example.com",
            bcrypt.hashSync("user2", salt),
            salt,
            Date("now"),
            0,
          ]);
          db.run(insert, [
            "user3",
            "user3@example.com",
            bcrypt.hashSync("user3", salt),
            salt,
            Date("now"),
            0,
          ]);
          db.run(insert, [
            "user4",
            "user4@example.com",
            bcrypt.hashSync("user4", salt),
            salt,
            Date("now"),
            0,
          ]);
        }
      }
    );
  }
});

module.exports = db;

app.use(
  express.urlencoded(),
  cors({
    origin: "http://localhost:3000",
  }),
  express.json()
);

// Root
app.get("/", (req, res) => {
  res.send("Welcome!");
});

// // List all the users
// app.get("/all/users", (req, res, next) => {
//   let sql = "SELECT * FROM Users";
//   let params = [];
//   db.all(sql, params, (err, rows) => {
//     if (err) {
//       res.status(400).json({ error: err.message });
//       return;
//     }
//     res.json({
//       msg: "success",
//       data: rows,
//     });
//   });
// });

// Admin signup
app.post("/admin/signup", async (req, res) => {
  let errors = [];
  try {
    let { Username, Email, Password } = req.body;
    if (!Username) {
      errors.push("Username is missing");
    }
    if (!Email) {
      errors.push("Email is missing");
    }
    if (errors.length) {
      res.status(400).json({ error: errors.join(",") });
      return;
    }
    let userExists = false;

    // Check if customer exists
    let sql = "SELECT * FROM Users WHERE Email = ? and Admin = 1";
    await db.all(sql, Email, (err, result) => {
      if (err) {
        res.status(402).json({ error: err.message });
        return;
      }

      // Insert customer if they don't exist
      if (result.length === 0) {
        let salt = bcrypt.genSaltSync(10);

        let data = {
          Username: Username,
          Email: Email,
          Password: bcrypt.hashSync(Password, salt),
          Salt: salt,
          DateCreated: Date("now"),
        };

        let sql =
          "INSERT INTO Users (Username, Email, Password, Salt, DateCreated, Admin) VALUES (?,?,?,?,?,?)";
        let params = [
          data.Username,
          data.Email,
          data.Password,
          data.Salt,
          Date("now"),
          1,
        ];
        let user = db.run(sql, params, function (err, innerResult) {
          if (err) {
            res.status(400).json({ error: err.message });
            return;
          }
        });
      } else {
        userExists = true;
      }
    });

    setTimeout(() => {
      if (!userExists) {
        res.status(201).json("Success");
      } else {
        res.status(201).json("Record already exists. Please login");
      }
    }, 500);
  } catch (err) {
    console.log(err);
  }
});

// Admin signin
app.post("/admin/signin", async (req, res) => {
  try {
    let { Email, Password } = req.body;
    // Make sure there is an Email and Password in the request
    if (!(Email && Password)) {
      res.status(400).send("All input is required");
    }

    let user = [];

    let sql = "SELECT * FROM Users WHERE Email = ? and Admin = 1";
    db.all(sql, Email, function (err, rows) {
      if (err) {
        res.status(400).json({ error: err.message });
        return;
      }

      rows.forEach(function (row) {
        user.push(row);
      });
      let PHash = bcrypt.hashSync(Password, user[0].Salt);

      if (PHash === user[0].Password) {
        // * CREATE JWT TOKEN
        let token = jwt.sign(
          {
            user_id: user[0].Id,
            username: user[0].Username,
            Email,
            Admin: user[0].Admin,
          },
          process.env.TOKEN_KEY,
          {
            expiresIn: "1h", // 60s = 60 seconds - (60m = 60 minutes, 2h = 2 hours, 2d = 2 days)
          }
        );

        user[0].Token = token;
      } else {
        return res.status(400).send("No Match");
      }

      return res.status(200).send(user);
    });
  } catch (err) {
    console.log(err);
  }
});

// Customer signup
app.post("/customer/signup", async (req, res) => {
  let errors = [];
  try {
    let { Username, Email, Password } = req.body;

    if (!Username) {
      errors.push("Username is missing");
    }
    if (!Email) {
      errors.push("Email is missing");
    }
    if (errors.length) {
      res.status(400).json({ error: errors.join(",") });
      return;
    }
    let userExists = false;

    // Check if customer exists
    let sql = "SELECT * FROM Users WHERE Email = ? and Admin = 0";
    await db.all(sql, Email, (err, result) => {
      if (err) {
        res.status(402).json({ error: err.message });
        return;
      }

      // Insert customer if they don't exist
      if (result.length === 0) {
        let salt = bcrypt.genSaltSync(10);

        let data = {
          Username: Username,
          Email: Email,
          Password: bcrypt.hashSync(Password, salt),
          Salt: salt,
          DateCreated: Date("now"),
        };

        let sql =
          "INSERT INTO Users (Username, Email, Password, Salt, DateCreated, Admin) VALUES (?,?,?,?,?,?)";
        let params = [
          data.Username,
          data.Email,
          data.Password,
          data.Salt,
          Date("now"),
          0,
        ];
        let user = db.run(sql, params, function (err, innerResult) {
          if (err) {
            res.status(400).json({ error: err.message });
            return;
          }
        });
      } else {
        userExists = true;
      }
    });

    setTimeout(() => {
      if (!userExists) {
        res.status(201).json("Success");
      } else {
        res.status(201).json("Record already exists. Please login");
      }
    }, 500);
  } catch (err) {
    console.log(err);
  }
});

// Customer signin
app.post("/customer/signin", async (req, res) => {
  try {
    let { Email, Password } = req.body;
    // Make sure there is an Email and Password in the request
    if (!(Email && Password)) {
      res.status(400).send("All input is required");
    }

    let user = [];

    let sql = "SELECT * FROM Users WHERE Email = ? and Admin = 0";
    db.all(sql, Email, function (err, rows) {
      if (err) {
        res.status(400).json({ error: err.message });
        return;
      }

      rows.forEach(function (row) {
        user.push(row);
      });
      let PHash = bcrypt.hashSync(Password, user[0].Salt);

      if (PHash === user[0].Password) {
        // * CREATE JWT TOKEN
        let token = jwt.sign(
          {
            user_id: user[0].Id,
            username: user[0].Username,
            Email,
            Admin: user[0].Admin,
          },
          process.env.TOKEN_KEY,
          {
            expiresIn: "1h", // 60s = 60 seconds - (60m = 60 minutes, 2h = 2 hours, 2d = 2 days)
          }
        );

        user[0].Token = token;
      } else {
        return res.status(400).send("No Match");
      }

      return res.status(200).send(user);
    });
  } catch (err) {
    console.log(err);
  }
});

// Admin content access
app.post("/admin/content", verifyTokenAdmin, (req, res) => {
  res.status(200).send("hello world");
});

// Customer content access
app.post("/customer/content", verifyTokenCustomer, (req, res) => {
  res.status(200).send("hello world");
});

app.listen(port, () => console.log(`API listening on port ${port}!`));
