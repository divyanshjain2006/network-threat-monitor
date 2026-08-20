const express = require("express");

const {
  executeResponse,
  getResponses,
} = require("../controllers/response.controller");

const router =
  express.Router();

router.get(
  "/",
  getResponses
);

router.post(
  "/execute",
  executeResponse
);

module.exports = router;