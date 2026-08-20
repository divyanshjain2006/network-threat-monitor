const express = require("express");

const {
  triggerScenario,
} = require(
  "../controllers/simulator.controller"
);

const router =
  express.Router();

router.post(
  "/scenario",
  triggerScenario
);

module.exports = router;