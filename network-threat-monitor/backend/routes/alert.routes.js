const express = require("express");

const {
  createAlert,
  getAlerts,
} = require("../controllers/alert.controller");

const router = express.Router();

router.get("/", getAlerts);

router.post("/", createAlert);

module.exports = router;