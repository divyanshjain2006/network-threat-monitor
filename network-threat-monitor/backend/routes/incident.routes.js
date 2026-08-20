const express = require("express");

const {
  createIncident,
  getIncidents,
  acknowledgeIncident,
} = require(
  "../controllers/incident.controller"
);

const router =
  express.Router();

router.get(
  "/",
  getIncidents
);

router.post(
  "/",
  createIncident
);

router.post(
  "/:incidentId/acknowledge",
  acknowledgeIncident
);

module.exports = router;