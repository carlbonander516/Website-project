// Global definitions
const adminName = 'admin'
// const adminPassword='GLbruteforce'
// sorry for not short password, when created I didn't think of it that you will need it
const adminPassword = '$2b$12$ih0mvvuOTDRnojbH7dAWNObupcWGehHxbBisxa43yFbH8WRtF93CS'

// BCRYPT
const bcrypt = require('bcrypt')
// salt round for bcrypt algorithm
const saltRounds = 12

/*  ----------DONT RUN MORE, ALREADY RAN---------
bcrypt.hash(adminPassword, saltRounds, function(err, hash) {
  if (err) {
    console.log("---> Error encrypting the password: ", err)
  } else {
    console.log("---> Hashed password (GENERATE only ONCE): ", hash)
  }
})
*/

// Packages

const session = require('express-session'); // sessions in express
const connectSqlite3 = require('connect-sqlite3'); // Store the sessions in a SQLite3 database file

const express = require('express');
const path = require('path');
const { engine } = require('express-handlebars'); // Import the engine
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose(); // Enable verbose mode for better error messages

const bodyParser = require('body-parser'); // required to get data from POSTS forms
const { release } = require('os');
const app = express();
const router = express.Router();

const PORT = 5050;

// Set up Handlebars as the view engine
app.engine('handlebars',
  engine({
    helpers: {
      eq(a, b) { return a == b; }
    }
  })
)
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views')); // Use path.join for cross-platform compatibility

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

// --------------Database setup----------------
const dbFile = 'projectdatabase.db';
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to the SQLite database.');
  }
});


// --------------Sessions----------------
const SQLiteStore = connectSqlite3(session); // store sessions in the database

// Storing the session in order to remember the user or admin
app.use(session({ 
  store: new SQLiteStore({ db: "session-db.db" }),
  saveUninitialized: false,
  resave: false,
  secret: "This123Is@Another#456GreatSecret678%Sentence",
  // Prevents cross-site request forgery  (From Linus lecture)
  cookie: {
    sameSite: 'strict',
    httpOnly: true,
    secure: false // Change to true if using HTTPS
  }
}))


app.use(function (req, res, next) {
  console.log("Session passed to response locals...")
  res.locals.session = req.session;
  next();
})


// ChatGPT fix, req.body was undefined and this fixed the issue
// Source: (ChatGPT, 2024, "req.body undefined", https://chatgpt.com/")
app.use(express.urlencoded({ extended: true }));
app.use(express.json());



// ---------------ROUTES------------------

// Route to login page
app.get('/login', (req, res) => {
  res.render('login.handlebars')
})

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Verification steps
  if (!username || !password) { // Check if both username and password contain some text
      const model = { error: "Username and password are required.", message: "" };
      return res.status(400).render('login.handlebars', model);
  }

  // Check if the username is the admin
  if (username === adminName) {
      // Compare the provided admin password
      bcrypt.compare(password, adminPassword, (err, result) => {
          if (err) {
              console.error("Error while comparing admin password: ", err);
              return res.status(500).render('login.handlebars', { error: "Error while processing login" });
          }
          if (result) {
              // Admin login successful
              req.session.isAdmin = true;
              req.session.isLoggedIn = true;
              req.session.username = username; // Store admin username in the session
              console.log("Admin logged in: ", username);
              return res.redirect('/'); // Redirect to the home page or admin dashboard
          } else {
              const model = { error: "Sorry, the password for admin is not correct...", message: "" };
              return res.status(400).render('login.handlebars', model);
          }
      });
  } else {
      // Query the database for the user
      db.get("SELECT passwordHash FROM users WHERE username = ?", [username], (err, row) => {
          if (err) {
              console.error("Database error: ", err);
              return res.status(500).render('login.handlebars', { error: "Database error" });
          }

          // Check if the user exists
          if (!row) {
              const model = { error: `Sorry, the username ${username} is not correct...`, message: "" };
              return res.status(400).render('login.handlebars', model);
          }

          // Compare the provided password with the hashed password in the database for regular users
          bcrypt.compare(password, row.passwordHash, (err, result) => {
              if (err) {
                  console.error("Error while comparing passwords: ", err);
                  return res.status(500).render('login.handlebars', { error: "Error while processing login" });
              }

              if (result) {
                  // Login successful for regular user
                  req.session.isLoggedIn = true;
                  req.session.username = username; // Store username in the session
                  console.log("User logged in: ", username);
                  return res.redirect('/'); // Redirect to the home page or user dashboard
              } else {
                  const model = { error: "Sorry, the password is not correct...", message: "" };
                  return res.status(400).render('login.handlebars', model);
              }
          });
      });
  }
});

// Create the default route "/"
app.get('/', function (req, res) {
  const model = {
    isLoggedIn: req.session.isLoggedIn,
    name: req.session.name,
    isAdmin: req.session.isAdmin
  }
  console.log("---> Home model: " + JSON.stringify(model))
  res.render('index', { title: 'Home Page' });
})

// Route to render the "movies" template
app.get('/movies/:movieid', function (req, res) {
  console.log("Movie route parameter movieid: " + JSON.stringify(req.params.movieid))
  // select in the table the movie with the given id
  db.get("SELECT * FROM allMovies WHERE mid=? LIMIT ? OFFSET ?", [req.params.movieid], (error, theMovie) => {
    if (error) {
      console.log("ERROR: ", error) // error: display in terminal
    } else {
        const model = {
        movie: theMovie
      }
    } res.render('movies.handlebars', model)
  })
})

// delete one specific movie
app.get('/movie/delete/:movieid', function (req, res) {
  if (req.session.isAdmin) {
    console.log("Movie route parameter movieid: " + JSON.stringify(req.params.movieid))
    // delete in the table the project with the given id
    db.run("DELETE FROM allMovies WHERE mid=?", [req.params.movieid], (error, theMovie) => {
      if (error) {
        console.log("ERROR: ", error) // error: display in terminal
      } else {
        console.log('The movie ' + req.params.movieid + ' has been deleted...')
        // redirect to the movies list route
        res.redirect('/movies')
      }
    })
  }
  else {
    console.log("You do not have permission to do this!")
    res.redirect('/')
  }
})

// Route for movies and part of Pagination code (pagination code is ChatGPT, referenced down below correctly)
app.get('/movies', function (req, res) {
  // Set the current page and limit (movies per page)
  // Source: (ChatGPT, 2024, "Create a dynamic pagination system, https://chatgpt.com/")
  const limit = 3; // Change this value for a different number of movies per page
  const page = parseInt(req.query.page) || 1; // Default to page 1 if not provided
  const offset = (page - 1) * limit; // Calculate the offset based on the current page
  // ChatGPT code ends here
  // Get the total count of movies
  db.get('SELECT COUNT(*) AS count FROM allMovies', (error, result) => {
    if (error) {
      console.log('ERROR: ', error);
      res.status(500).send('Database error');
    } 
    // Source: (ChatGPT, 2024, "Create a dynamic pagination system, https://chatgpt.com/")
    else { 
      const totalMovies = result.count;
      const totalPages = Math.ceil(totalMovies / limit);

      db.all('SELECT * FROM allMovies LIMIT ? OFFSET ?', [limit, offset], (error, listOfMovies) => {
        if (error) {
          console.log('ERROR: ', error);
          res.status(500).send('Database error');
        } else {
          // Pass the movies and pagination info to the template
          const model = {
            movies: listOfMovies,
            currentPage: page,
            totalPages: totalPages
          }; // ChatGPT code ends here.
          res.render('movies.handlebars', model);
        }
      });
    }
  });
});


//create new movie form, fetch category from allCategories table
app.get('/movie/new', function(req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.render('movies.handlebars')
  }
  db.all("SELECT * FROM allCategories", [], (error, categories) => {
    if (error) {
      console.log("ERROR: ", error);
      res.redirect('/movies');
    } else {
      res.render('movie-new.handlebars', { categories: categories });
    }
  });
});

// Creating a new movie, including inserting the new movie into table
app.post('/movie/new', function (req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('movies.handlebars')
  }
  const name = req.body.moviename
  const mreleasedate = req.body.movieyear
  const category = req.body.moviecategory
  const url = req.body.movieurl
  const desc = req.body.moviedesc
  db.run("INSERT INTO allMovies (mname, mreleasedate, mcategory, mimgURL, mdesc) VALUES (?, ?, ?, ?, ?)",
    [name, mreleasedate, category, url, desc], (error) => {
      if (error) {
        console.log("ERROR: ", error)
        res.redirect('/movies')
      } else {
        console.log("Line added into the allMovies table!")
        res.redirect('/movies')
      }
    })
})

// Route to modify movie
app.get('/movie/modify/:movieid', function(req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('movies.handlebars')
  }
  const movieid = req.params.movieid;

  // Query to get the movie details
  const sqlMovie = `SELECT * FROM allMovies WHERE mid = ?`;
  
  // Query to get all categories
  const sqlCategories = `SELECT * FROM allCategories`;

  db.get(sqlMovie, [movieid], (error, movie) => {
    if (error) {
      console.log("ERROR: ", error);
      res.redirect('/movies');
    } else {
      db.all(sqlCategories, [], (error, categories) => {
        if (error) {
          console.log("ERROR: ", error);
          res.redirect('/movies');
        } else {
          res.render('movie-new.handlebars', { movie: movie, categories: categories });
        }
      });
    }
  });
});


// In order to modify a movie for admin
app.post('/movie/modify/:movieid', function (req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('movies.handlebars')
  }
  const movieid = req.params.movieid;
  const name = req.body.moviename;
  const mreleasedate = req.body.movieyear;
  const category = req.body.moviecategory;
  const url = req.body.movieurl;
  const desc = req.body.moviedesc;

  const sql = `
    UPDATE allMovies 
    SET mname = ?, mreleasedate = ?, mcategory = ?, mimgURL = ?, mdesc = ? 
    WHERE mid = ?
  `;

  db.run(sql, [name, mreleasedate, category, url, desc, movieid], (error) => {
    if (error) {
      console.log("ERROR: ", error);
      res.redirect('/movies'); // Redirect on error
    } else {
      console.log("Movie updated successfully in the allMovies table!");
      res.redirect('/movies'); // Redirect on success
    }
  });
});






// Route to render the "information2" template
// Creates an inner join in order to be able to get
// the category info from allCategories
app.get('/information/movies/:movieid', function(req, res) {
  const id = req.params.movieid
  const sql = `SELECT allMovies.mid, allMovies.mname, allCategories.cname AS category_name, allMovies.mreleasedate, allMovies.mimgURL, allMovies.mdesc
  FROM allMovies INNER JOIN allCategories ON allMovies.mcategory = allCategories.cid WHERE allMovies.mid = ?`;
  db.get(sql, [id], (error, theMovie) => {
    if(error) {
      console.log("ERROR: ", error)
      res.redirect('/movies')
    } else {
      model = { movie: theMovie }
      res.render('information2.handlebars', model)
    }
  })
})

// Route to serve the modify form for a specific series
app.get('/serie/modify/:serieid', function(req, res){
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('series.handlebars')
  }
  const serieid = req.params.serieid;
  const sqlSerie = `SELECT * FROM allSeries WHERE sid = ?`;
  const sqlCategories = `SELECT * FROM allCategories`;

  db.get(sqlSerie, [serieid], (error, serie) => {
    if(error){
      console.log("ERROR: ", error);
      res.redirect('/series');
    } else{
      db.all(sqlCategories, [], (error, categories) => {
        if(error){
          console.log("ERROR: ", error);
          res.redirect('/series');
        } else {
          res.render('serie-new.handlebars', { serie: serie, categories: categories });
        }
      })
    }
  })
})

// Route to handle the form submission for modifying a series
app.post('/serie/modify/:serieid', function(req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('series.handlebars')
  }
  const serieid = req.params.serieid; // Correctly get the serieid from params
  const name = req.body.seriename;
  const sreleasedate = req.body.serieyear;
  const category = req.body.seriecategory; // Corrected from req.body.serieurl
  const url = req.body.serieurl;
  const desc = req.body.seriedesc || ''; // Ensure we provide a default value if undefined

  const sql = `
  UPDATE allSeries
  SET sname = ?, sreleasedate = ?, scategory = ?, simgURL = ?, sdesc = ?
  WHERE sid = ?`;

  db.run(sql, [name, sreleasedate, category, url, desc, serieid], (error) => {
    if (error) {
      console.log("ERROR: ", error);
      res.redirect('/series');
    } else {
      console.log("Serie updated successfully in the allSeries table");
      res.redirect('/series');
    }
  });
});


// delete one specific serie
app.get('/serie/delete/:serieid', function (req, res) {
  if (req.session.isAdmin) {
    console.log("Serie route parameter serieid: " + JSON.stringify(req.params.serieid))
    // delete in the table the serie with the given id
    db.run("DELETE FROM allSeries WHERE sid=?", [req.params.serieid], (error, theSerie) => {
      if (error) {
        console.log("ERROR: ", error) // error: display in terminal
      } else {
        console.log('The serie ' + req.params.serieid + ' has been deleted...')
        // redirect to the series list route
        res.redirect('/series')
      }
    })
  }
  else {
    console.log("You do not have permission to do this!")
    res.redirect('/')
  }
})

app.get('/series', function (req, res) {
  const limit = 3;
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * limit;

  // Get the total count of series
  db.get('SELECT COUNT(*) AS count FROM allSeries', (error, result) => {
    if (error) {
      console.log('ERROR: ', error);
      res.status(500).send('Database error');
    } else {
      const totalSeries = result.count;
      const totalPages = Math.ceil(totalSeries / limit);

      // Fetch series with pagination
      db.all('SELECT * FROM allSeries LIMIT ? OFFSET ?', [limit, offset], (error, listOfSeries) => {
        if (error) {
          console.log('ERROR: ', error);
          res.status(500).send('Database error');
        } else {
          const model = {
            series: listOfSeries,
            currentPage: page,
            totalPages: totalPages
          };
          res.render('series.handlebars', model);
        }
      });
    }
  });
});


//create new serie form
app.get('/serie/new', function (req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('series.handlebars')
  }
  db.all("SELECT * FROM allCategories", [], (error, categories) => {
    if(error) {
      console.log("ERROR: ", error);
      res.redirect('/series');
    } else {
      res.render('serie-new.handlebars', { categories: categories });
    }
  })
})

app.post('/serie/new', function (req, res) {
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('series.handlebars')
  }

  const name = req.body.seriename
  const releasedate = req.body.serieyear
  const category = req.body.seriecategory
  const url = req.body.serieurl
  const desc = req.body.seriedesc
  db.run("INSERT INTO allSeries (sname, sreleasedate, scategory, simgURL, sdesc) VALUES (?, ?, ?, ?, ?)",
    [name, releasedate, category, url, desc], (error) => {
      if (error) {
        console.log("ERROR: ", error)
        res.redirect('/series')
      } else {
        console.log("Line added into the allSeries table!")
        res.redirect('/series')
      }
    })
})


// Route to render the "information" template
app.get('/information/series/:serieid', function(req, res){
  const id = req.params.serieid;
  const sql = `SELECT allSeries.sid, allSeries.sname, allCategories.cname AS category_name, 
  allSeries.sreleasedate, allSeries.simgURL, allSeries.sdesc
  FROM allSeries INNER JOIN allCategories ON allSeries.scategory = allCategories.cid WHERE allSeries.sid = ?`;
  db.get(sql, [id], (error, theSerie) => {
    if(error){
      console.log("ERROR: ", error)
      res.redirect('/series')
    } else {
      model = { serie: theSerie }
      res.render('information.handlebars', model)
    }
  })
})


app.use(express.static('public'))
app.use(express.urlencoded({ extended: true }));



// Route to logout
app.get('/logout', (req, res) => { //logout function
  req.session.destroy((err) => { // destroy current session
    if (err) {
      console.log("Error while destroying the session ", err)
    } else {
      console.log('Logged out...')
      res.redirect('/')
    }
  })
})

// Route to contact page
app.get('/contact', (req, res) => {
  res.render('contact.handlebars')
})

// Route to series page
app.get('/series', (req, res) => {
  res.render('series.handlebars')
})

// Route to about page
app.get('/about', (req, res) => {
  res.render('about.handlebars')
})

app.get('/register', (req,res) => {
  res.render('register.handlebars')
})

// Creating register post, the register form
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  console.log('Username:', username);
  console.log('Password:', password);
  // Required username and password in register box
  if (!username || !password) {
      const model = { error: "Username and password are required." };
      return res.status(400).render('register.handlebars', model);
  }
  // Hashing the password
  bcrypt.hash(password, saltRounds, (err, hash) => {
      if (err) {
          console.log("Hashing error:", err); // Log the error
          return res.status(500).render('register.handlebars', { error: "Error hashing password: " + err.message });
      }
      console.log('Hashed password:', hash); // Log the hash
      // Inserting user into users table with their username and hashed password.
      db.run("INSERT INTO users (username, passwordHash) VALUES (?, ?)", [username, hash], (error) => {
          if (error) {
              const model = { error: "Error while inserting user: " + error.message };
              return res.status(500).render('register.handlebars', model);
          }
          res.redirect('/login');
      });
  });
});


app.get('/users', function (req, res) {
  // Check if the user is logged in and is an admin
  if (req.session.isLoggedIn && req.session.isAdmin) {
    // Fetch all users from the database
    db.all('SELECT * FROM users', function (err, allUsers) {
      if (err) {
        console.log('Error: ' + err);
        res.status(500).send('Error within the database.');
      } else {
        // Render the users.handlebars template and pass the user data
        res.render('users.handlebars', { users: allUsers });
      }
    });
  } else {
    res.status(403).send("Access denied. Admins only.");
  }
});

// Route to get the modify page for a user (only accessible by admin)
app.get('/user/modify/:userid', function (req, res) {
  // Check if the user is an admin
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.render('index.handlebars')
  }

  const id = req.params.userid;
  
  // Fetch the user by id
  db.get("SELECT * FROM users WHERE id=?", [id], (error, user) => {
    if (error) {
      console.log("ERROR: ", error);
      return res.redirect('/users');
    } else {
      // Render a form for modifying user details
      res.render('user-modify.handlebars', { user }); // Create this new Handlebars file
    }
  });
});


// Route to handle updating the user (only accessible by admin)
app.post('/user/modify/:userid', function (req, res) {
  // Check if the user is an admin
  if (!req.session.isAdmin) {
    // If the user is not an admin, redirect to a different page or send a forbidden message
    return res.redirect('index.handlebars')
  }

  const id = req.params.userid;
  const newUsername = req.body.username; // Get the new username from the form
  const newPassword = req.body.password; // Get the new password from the form

  // Prepare the SQL statement to update user
  let sql = "UPDATE users SET username = ?";
  const params = [newUsername];

  // Check if a new password is provided
  if (newPassword) {
    // Hash the new password before updating it
    bcrypt.hash(newPassword, saltRounds, (err, hash) => {
      if (err) {
        console.log("Hashing error:", err);
        return res.redirect('/users');
      }

      // Add password update to SQL and parameters
      sql += ", passwordHash = ?";
      params.push(hash); // Add hashed password to parameters
      sql += " WHERE id = ?";
      params.push(id); // Add user ID to parameters

      // Run the update query
      db.run(sql, params, (error) => {
        if (error) {
          console.log("ERROR: ", error);
        }
        res.redirect('/users'); // Redirect back to the user list
      });
    });
  } else {
    // If no password is provided, just update the username
    sql += " WHERE id = ?";
    params.push(id);

    db.run(sql, params, (error) => {
      if (error) {
        console.log("ERROR: ", error);
      }
      res.redirect('/users'); // Redirect back to the user list
    });
  }
});



// Delete a specific user
app.get('/user/delete/:userid', function (req, res) {
  if (req.session.isAdmin) {
    const userId = req.params.userid;
    // Delete the user with the given id
    db.run("DELETE FROM users WHERE id=?", [userId], (error) => {
      if (error) {
        console.log("ERROR: ", error); // Log the error
      } else {
        console.log('User ' + userId + ' has been deleted...');
        res.redirect('/users'); // Redirect to the users list
      }
    });
  } else {
    console.log("You do not have permission to do this!");
    res.redirect('/'); // Redirect unauthorized access
  }
});



//---------------
// 404 NOT FOUND -- source: (Stack overflow, 2016, https://stackoverflow.com/questions/37357687/express-handlebars-page-is-routing-to-404)
// --------------
app.use(function (req, res) {
  res.status(404).render('404.handlebars');
})

// ---------
// 500 ERROR -- source: (Stack overflow, 2016, https://stackoverflow.com/questions/37357687/express-handlebars-page-is-routing-to-404)
// ---------
app.use(function (err, req, res, next) {
  console.error(err.stack);
  res.status(500).render('500');
});

// Start the server
app.listen(PORT, function () {
  // initTableMovies(db) // create the table movies and populate it
  // initTableSeries(db) // create the table series and populate it
  // initTableCategories(db) // create the table categories and populate it
  // initTableUsers(db); // creating users table

  // displays a message in the terminal when the server is listening
  console.log(`Server is running on http://localhost:${PORT}`);
})


// --------------
// USER FUNCTIONS
// --------------

// MODEL for the movies
function initTableMovies(db) {
  const allMovies = [
    { "id": "1", "name": "Interstellar", "category": "1", "releasedate": "2014", "imgURL": "interstellar.jpg", 
      "desc": "A space adventure to save humanity." },
    { "id": "2", "name": "Captain Philips", "category": "2", "releasedate": "2013", "imgURL": "cptphilips.jpg", 
      "desc": "Ship gets hijacked by somali pirates." },
    { "id": "3", "name": "I Am Legend", "category": "2", "releasedate": "2007", "imgURL": "imlegend.jpg", 
      "desc": "The known world gets infected by some virus, a man and his dog tries to cure it." },
    { "id": "4", "name": "Independence day: Resurgence", "category": "1", "releasedate": "2016", "imgURL": "indepday.jpg",
      "desc": "Aliens invade planet earth. The second time." },
    { "id": "5", "name": "The Maze Runner", "category": "1", "releasedate": "2014", "imgURL": "mazerunner.jpg", 
      "desc": "A teenager wakes up in the middle of a maze and tries to get out." },
    { "id": "6", "name": "The Notebook", "category": "3", "releasedate": "2004", "imgURL": "thenotebook.jpg", 
      "desc": "A romantic love story in the 1900s." },
    { "id": "7", "name": "Guardians of the Galaxy", "category": "1", "releasedate": "2014", "imgURL": "guardiansgalaxy.jpg", 
      "desc": "A funny marvel superhero movie." },
    { "id": "8", "name": "Lord Of The Rings: The Fellowship of the Ring", "category": "4", "releasedate": "2001", "imgURL": "lotr1.jpg", 
      "desc": "The first LOTR movie. No spoilers on this one." },
    { "id": "9", "name": "Schindlers List", "category": "5", "releasedate": "1993", "imgURL": "schindlers list.jpg", 
      "desc": "A WW2 story about how poorly the nazis treated jews." },
    { "id": "10", "name": "Timetrap", "category": "1", "releasedate": "2017", "imgURL": "timetrap.jpg", 
      "desc": "A group gets stuck in a weird cave where time doesn't work correctly." },
    { "id": "11", "name": "Fightclub", "category": "2", "releasedate": "1999", "imgURL": "fightclub.jpg", 
      "desc": "Fightclub is an underground club where they fight a lot." },
    { "id": "12", "name": "Matrix", "category": "2", "releasedate": "1999", "imgURL": "matrix.jpg", 
      "desc": "Stuck in the matrix. Wooooo." },
    { "id": "13", "name": "Back to the future", "category": "1", "releasedate": "1985", "imgURL": "back2thefuture.jpg", 
      "desc": "Travels to future, obviously." },
    { "id": "14", "name": "Home Alone", "category": "6", "releasedate": "1990", "imgURL": "homealone.jpg", 
      "desc": "Is obviously about a kid that is home alone during xmas." },
    { "id": "15", "name": "The Conjuring", "category": "7", "releasedate": "2013", "imgURL": "theconjuring.jpg", 
      "desc": "Horror movie with good sequels and story." },
  ];
  
// creating allMovies table
  db.run(
    "CREATE TABLE IF NOT EXISTS allMovies (mid INTEGER PRIMARY KEY AUTOINCREMENT, mname TEXT NOT NULL, mcategory INTEGER NOT NULL, mreleasedate INTEGER NOT NULL, mimgURL TEXT NOT NULL, mdesc TEXT NOT NULL, FOREIGN KEY (mcategory) REFERENCES allCategories(cid))",
    (error) => {
      if (error) {
        console.log("ERROR: ", error); // Error: display it in the terminal
      } else {
        console.log("---> Table allMovies created!");

        // Insert movies into the table
        allMovies.forEach((oneMovie) => {
          db.run(
            "INSERT INTO allMovies (mid, mname, mcategory, mreleasedate, mimgURL, mdesc) VALUES (?, ?, ?, ?, ?, ?)",
            [oneMovie.id, oneMovie.name, oneMovie.category, oneMovie.releasedate, oneMovie.imgURL, oneMovie.desc], (error) => {
              if (error) {
                console.log("ERROR: ", error);
              } else {
                console.log("Line added into the allMovies table!");
              }
            }
          );
        });
      }
    }
  );
}


function initTableSeries(db) {
  // MODEL for series
  const allSeries = [
    { "id": "1", "name": "The Walking Dead", "category": "2", "releasedate": "2010", "imgURL": "thewalkingdead.jpg", 
      "desc": "Apocalyptic zombie world. Follow Rick Grimes adventures" },
    { "id": "2", "name": "Game Of Thrones", "category": "4", "releasedate": "2011", "imgURL": "gameofthrones.jpg", 
      "desc": "Fantasy World, named as one of the worlds best series" },
    { "id": "3", "name": "The Vampire Diaries", "category": "2", "releasedate": "2009", "imgURL": "tvd.jpg", 
      "desc": "Fantasy world about vampires and werewolfs." },
    { "id": "4", "name": "Peaky Blinders", "category": "2", "releasedate": "2013", "imgURL": "peakyblinders.jpg", 
      "desc": "Series following the birmingham gang Peaky Blinders in the early 1900s." },
    { "id": "5", "name": "Teen Wolf", "category": "4", "releasedate": "2011", "imgURL": "teenwolf.jpg", 
      "desc": "Series about werewolfs mixed with highschool teenage life." },
    { "id": "6", "name": "The Perfect Couple", "category": "3", "releasedate": "2024", "imgURL": "perfectcouple.jpg", 
      "desc": "Series about a perfect couple." },
    { "id": "7", "name": "Prison Break", "category": "2", "releasedate": "2005", "imgURL": "prisonbreak.jpg", 
      "desc": "Series about breaking out of a prison." },
    { "id": "8", "name": "Arcane", "category": "1", "releasedate": "2021", "imgURL": "arcane.jpg", 
      "desc": "Series based on videogame League of Legends." },
    { "id": "9", "name": "Dark Matter", "category": "1", "releasedate": "2024", "imgURL": "darkmatter.jpg", 
      "desc": "Series based on dark matter stuff." },
    { "id": "10", "name": "The Expanse", "category": "1", "releasedate": "2015", "imgURL": "theexpanse.jpg", 
      "desc": "Futuristic series about earth, space and mars" },
    { "id": "11", "name": "Foundation", "category": "1", "releasedate": "2021", "imgURL": "foundation.jpg", 
      "desc": "Sci-fi series." },
    { "id": "12", "name": "Haunting of Hill House", "category": "7", "releasedate": "2018", "imgURL": "hauntingofhillhouse.jpg", 
      "desc": "Horror series about a haunted house." },
    { "id": "13", "name": "The Watcher", "category": "7", "releasedate": "2024", "imgURL": "thewatcher.jpg", 
      "desc": "Horror serie about being watched" },
    { "id": "14", "name": "The Originals", "category": "2", "releasedate": "2013", "imgURL": "theoriginals.jpg", 
      "desc": "Built on the vampire diaries, fantasy or action serie" },
    { "id": "15", "name": "Virgin River", "category": "3", "releasedate": "2019", "imgURL": "virginriver.jpg", 
      "desc": "Romantic show based in the place virgin river." }
  ];
  
// Creating allSeries table
  db.run(
    "CREATE TABLE IF NOT EXISTS allSeries (sid INTEGER PRIMARY KEY AUTOINCREMENT, sname TEXT NOT NULL, scategory INTEGER NOT NULL, sreleasedate INTEGER, simgURL TEXT, sdesc TEXT NOT NULL, FOREIGN KEY (scategory) REFERENCES allCategories(cid) )",
    (error) => {
      if (error) {
        console.log("ERROR: ", error); // Error: display it in the terminal
      } else {
        console.log("---> Table allSeries created!");

        // Insert series into the table
        allSeries.forEach((oneSerie) => {
          db.run(
            "INSERT INTO allSeries (sid, sname, scategory, sreleasedate, simgURL, sdesc) VALUES (?, ?, ?, ?, ?, ?)",
            [oneSerie.id, oneSerie.name, oneSerie.category, oneSerie.releasedate, oneSerie.imgURL, oneSerie.desc],
            (error) => {
              if (error) {
                console.log("ERROR: ", error);
              } else {
                console.log("Line added into the allSeries table!");
              }
            }
          );
        });
      }
    }
  );
}
/*
db.all('SELECT * FROM allMovies', [], (err, rows) => {
  if (err) {
      throw err; // Handle error
  }
  console.log(rows); // Log the rows to the console
});
*/

function initTableCategories(db) {
  // MODEL for categories
  const allCategories = [
    { "id": "1", "name": "Sci-fi", "desc": "Speculative fiction, usually futuristics concepts and imaginative."},
    { "id": "2", "name": "Action", "desc": "The genre action is spectacular physical action, might include explosions or fights and such like style." },
    { "id": "3", "name": "Romantic", "desc": "Romantic movies, such as the Notebook." },
    { "id": "4", "name": "Fantasy", "desc": "These movies are a lot of fantasy that might use fantasy creatures like werewolfs, vampires or dragons."},
    { "id": "5", "name": "War", "desc": "War movies usually either involve war directly or it is more used indirectly in the movie."},
    { "id": "6", "name": "Comedy", "desc": "Comedy movies are funny movies that you should laugh about, unless they are bad."},
    { "id": "7", "name": "Horror", "desc": "Scary movies that is making you jump out of your seat at the cinema."},
  ];
//creating allCategories table
  db.run(
    "CREATE TABLE IF NOT EXISTS allCategories (cid INTEGER PRIMARY KEY AUTOINCREMENT, cname TEXT NOT NULL, cdesc TEXT NOT NULL)",
    (error) => {
      if (error) {
        console.log("ERROR: ", error); // Error: display it in the terminal
      } else {
        console.log("---> Table allCategories created!");

        // Insert categories into the table
        allCategories.forEach((oneCategory) => {
          db.run(
            "INSERT INTO allCategories (cid, cname, cdesc) VALUES (?, ?, ?)",
            [oneCategory.id, oneCategory.name, oneCategory.desc],
            (error) => {
              if (error) {
                console.log("ERROR: ", error);
              } else {
                console.log("Line added into the allCategories table!");
              }
            }
          );
        });
      }
    }
  );
}

// CREATING USERS TABLE
function initTableUsers(db) {
  // Create USERS table
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL)",
    (error) => {
      if (error) {
        console.log("ERROR: ", error);
      } else {
        console.log("---> Table USERS created!");
      }
    }
  );
}



// All code below generated by ChatGPT
// Source: (ChatGPT, 2024, "Create a dynamic pagination system, https://chatgpt.com/")

const handlebars = require('handlebars');

handlebars.registerHelper('add', function(a, b) {
  return a + b;
});

handlebars.registerHelper('subtract', function(a, b) {
  return a - b;
});

handlebars.registerHelper('eq', function(a, b) {
  return a === b;
});

handlebars.registerHelper('gt', function(a, b) {
  return a > b;
});

handlebars.registerHelper('lt', function(a, b) {
  return a < b;
});

handlebars.registerHelper('range', function(start, end) {
  const range = [];
  for (let i = start; i <= end; i++) {
    range.push(i);
  }
  return range;
});
