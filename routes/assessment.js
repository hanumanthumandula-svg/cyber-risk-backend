const express = require('express');
const router = express.Router();
const Assessment = require('../models/Assessment');

// Save a new assessment
router.post('/save', async (req, res) => {
  try {
    const assessment = new Assessment(req.body);
    const saved = await assessment.save();
    res.json({ success: true, id: saved._id });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get all assessments
router.get('/all', async (req, res) => {
  try {
    const assessments = await Assessment.find().sort({ createdAt: -1 });
    res.json(assessments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get single assessment by ID
router.get('/:id', async (req, res) => {
  try {
    const assessment = await Assessment.findById(req.params.id);
    res.json(assessment);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;