const mongoose = require('mongoose');

const AssessmentSchema = new mongoose.Schema({
  assets: [String],
  answers: Object,
  scores: Object,
  overallScore: Number,
  riskLevel: String,
  recommendations: [String],
  createdAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Assessment', AssessmentSchema);