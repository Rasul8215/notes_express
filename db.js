const fs = require("fs");

class DataBase {
  // create a file with fileName
  constructor(fileName = "db") {
    this.fileName = fileName + ".json";
    fs.appendFileSync(this.fileName, "");
  }

  read(table, id) {
    const db = JSON.parse(
      fs.readFileSync(this.fileName, { encoding: "utf-8" }) || "{}"
    );
    if (id) {
      return db?.[table]?.[id];
    }

    return Object.keys(db?.[table] || {}).map((rowID) => ({
      id: rowID,
      ...db?.[table]?.[rowID],
    }));
  }

  create(table, data) {
    const db = JSON.parse(
      fs.readFileSync(this.fileName, { encoding: "utf-8" }) || "{}"
    );
    const id = Object.keys(db[table] || {})?.length + 1 || 1;

    db[table] = { ...db[table], [id]: data };

    fs.writeFileSync(this.fileName, JSON.stringify(db));
    return data;
  }

  update(table, id, data) {
    const db = JSON.parse(
      fs.readFileSync(this.fileName, { encoding: "utf-8" }) || "{}"
    );

    db[table][id] = { ...db[table]?.[id], ...data };

    fs.writeFileSync(this.fileName, JSON.stringify(db));
    return data;
  }

  delete(table, id) {
    const db = JSON.parse(
      fs.readFileSync(this.fileName, { encoding: "utf-8" }) || "{}"
    );

    db[table][id] = undefined;

    fs.writeFileSync(this.fileName, JSON.stringify(db));
    return true;
  }
}

module.exports = DataBase;
