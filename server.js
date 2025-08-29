
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
require('dotenv').config();

const app = express();

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',`${process.env.FRONTEND_URL}`);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, Pragma');

  if (req.method === 'OPTIONS') {
    console.log('OPTIONS preflight request received for:', req.path);
    res.status(200).end();
    return;
  }
  
  next();
});

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting 
const financialRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many financial data requests',
  skip: (req) => req.method === 'OPTIONS' 
});

app.use('/api/financial', financialRateLimit);

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  referralCode: { type: String, unique: true },
  referredBy: { type: String },
  referralCount: { type: Number, default: 0 },
  referralRewards: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Generate referral code
const generateReferralCode = (firstName, lastName) => {
  const random = Math.random().toString(36).substring(2, 8).toUpperCase();
  return `${firstName.substring(0, 2)}${lastName.substring(0, 2)}${random}`;
};

// Auth middleware - SKIP for OPTIONS requests
const authenticateToken = (req, res, next) => {
  if (req.method === 'OPTIONS') {
    return next();
  }

  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log('Auth check for:', req.method, req.path);
  console.log('Token present:', !!token);
  
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret', (err, user) => {
    if (err) {
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Test endpoint
app.get('/api/health', (req, res) => {
  console.log('Health check requested');
  res.json({ 
    message: 'Server is running', 
    timestamp: new Date().toISOString(),
    cors: 'enabled'
  });
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('Register request received:', req.body?.email);
    const { email, password, firstName, lastName, referralCode } = req.body;
    
    if (!email || !password || !firstName || !lastName) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const userReferralCode = generateReferralCode(firstName, lastName);
    
    let referredBy = null;
    let newUserReferralRewards = 0; 
    
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) {
        referredBy = referrer._id;
        
        await User.findByIdAndUpdate(referrer._id, {
          $inc: { referralCount: 1, referralRewards: 10 }
        });
        
        newUserReferralRewards = 10;
      }
    }
    
    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      referralCode: userReferralCode,
      referredBy,
      referralRewards: newUserReferralRewards 
    });
    
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );
    
    console.log('User registered successfully:', user.email);
    
    res.status(201).json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        referralCode: user.referralCode,
        referralCount: user.referralCount || 0,
        referralRewards: user.referralRewards || 0
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('Login request received:', req.body?.email);
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Invalid password for user:', email);
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );
    
    console.log('User logged in successfully:', user.email);
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        referralRewards: user.referralRewards
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get current user endpoint
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    console.log('Get user info for:', req.user?.userId);
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        referralRewards: user.referralRewards
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mock Financial Data
const generateMockTransactions = (userId) => {
  const transactions = [];
  const categories = ['Food & Dining', 'Shopping', 'Gas & Transport', 'Bills & Utilities', 'Entertainment'];
  const merchants = ['Starbucks', 'Amazon', 'Shell', 'Electric Company', 'Netflix', 'Grocery Store', 'Restaurant'];
  
  for (let i = 0; i < 20; i++) {
    const amount = (Math.random() * 200 + 10).toFixed(2);
    const date = new Date();
    date.setDate(date.getDate() - Math.floor(Math.random() * 30));
    
    transactions.push({
      id: `txn_${Date.now()}_${i}`,
      amount: parseFloat(amount),
      description: merchants[Math.floor(Math.random() * merchants.length)],
      category: categories[Math.floor(Math.random() * categories.length)],
      date: date.toISOString(),
      type: Math.random() > 0.8 ? 'credit' : 'debit'
    });
  }
  
  return transactions.sort((a, b) => new Date(b.date) - new Date(a.date));
};

// Get financial data
app.get('/api/financial/dashboard', authenticateToken, async (req, res) => {
  try {
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const transactions = generateMockTransactions(req.user.userId);
    const balance = 2347.82;
    const monthlySpending = transactions
      .filter(t => t.type === 'debit')
      .reduce((sum, t) => sum + t.amount, 0);
    
    const spendingInsights = {
      topCategory: 'Food & Dining',
      monthlyTrend: 'up',
      recommendation: 'Consider setting a budget limit for dining expenses',
      savingsOpportunity: 127.50
    };
    
    res.json({
      balance,
      transactions,
      monthlySpending: monthlySpending.toFixed(2),
      insights: spendingInsights
    });
  } catch (error) {
    console.error('Financial data error:', error);
    res.status(500).json({ message: 'Error fetching financial data' });
  }
});

// Get referral stats
app.get('/api/referrals', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const referredUsers = await User.find({ referredBy: req.user.userId })
      .select('firstName lastName createdAt')
      .sort({ createdAt: -1 });
    
    res.json({
      referralCode: user.referralCode,
      totalReferrals: user.referralCount,
      totalRewards: user.referralRewards,
      referredUsers
    });
  } catch (error) {
    console.error('Referral stats error:', error);
    res.status(500).json({ message: 'Error fetching referral stats' });
  }
});



// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['income', 'expense'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  date: { type: Date, required: true },
  notes: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Add transaction endpoint
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
    console.log('Add transaction request for user:', req.user?.userId);
    console.log('Transaction data:', req.body);

    const { type, amount, description, category, date, notes } = req.body;

    // Validation
    if (!type || !amount || !description || !category || !date) {
      return res.status(400).json({ 
        message: 'Missing required fields: type, amount, description, category, date' 
      });
    }

    if (!['income', 'expense'].includes(type)) {
      return res.status(400).json({ 
        message: 'Type must be either "income" or "expense"' 
      });
    }

    if (amount <= 0) {
      return res.status(400).json({ 
        message: 'Amount must be greater than 0' 
      });
    }

    // Create new transaction
    const transaction = new Transaction({
      userId: req.user.userId,
      type,
      amount: Math.abs(amount), 
      description: description.trim(),
      category,
      date: new Date(date),
      notes: notes ? notes.trim() : undefined
    });

    await transaction.save();

    console.log('Transaction created successfully:', transaction._id);

    res.status(201).json({
      message: 'Transaction added successfully',
      transaction: {
        id: transaction._id,
        type: transaction.type,
        amount: transaction.amount,
        description: transaction.description,
        category: transaction.category,
        date: transaction.date,
        notes: transaction.notes,
        createdAt: transaction.createdAt
      }
    });

  } catch (error) {
    console.error('Add transaction error:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message 
    });
  }
});

// Get user transactions endpoint
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    console.log('Get transactions request for user:', req.user?.userId);

    const { page = 1, limit = 20, type, category, startDate, endDate } = req.query;

    const query = { userId: req.user.userId };

    if (type && ['income', 'expense'].includes(type)) {
      query.type = type;
    }

    if (category) {
      query.category = category;
    }

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate);
      if (endDate) query.date.$lte = new Date(endDate);
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const transactions = await Transaction.find(query)
      .sort({ date: -1, createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Transaction.countDocuments(query);

    const formattedTransactions = transactions.map(t => ({
      id: t._id,
      type: t.type,
      amount: t.type === 'expense' ? -t.amount : t.amount,
      description: t.description,
      category: t.category,
      date: t.date.toISOString().split('T')[0], 
      notes: t.notes,
      createdAt: t.createdAt
    }));

    res.json({
      transactions: formattedTransactions,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: totalCount,
        totalPages: Math.ceil(totalCount / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ 
      message: 'Error fetching transactions', 
      error: error.message 
    });
  }
});

// Update transaction endpoint
app.put('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    console.log('Update transaction request:', req.params.id, 'for user:', req.user?.userId);

    const { type, amount, description, category, date, notes } = req.body;
    const transactionId = req.params.id;

    const transaction = await Transaction.findOne({
      _id: transactionId,
      userId: req.user.userId
    });

    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }

    // Validation
    if (type && !['income', 'expense'].includes(type)) {
      return res.status(400).json({ 
        message: 'Type must be either "income" or "expense"' 
      });
    }

    if (amount !== undefined && amount <= 0) {
      return res.status(400).json({ 
        message: 'Amount must be greater than 0' 
      });
    }

    const updates = {
      updatedAt: new Date()
    };

    if (type) updates.type = type;
    if (amount) updates.amount = Math.abs(amount);
    if (description) updates.description = description.trim();
    if (category) updates.category = category;
    if (date) updates.date = new Date(date);
    if (notes !== undefined) updates.notes = notes ? notes.trim() : undefined;

    const updatedTransaction = await Transaction.findByIdAndUpdate(
      transactionId,
      updates,
      { new: true }
    );

    console.log('Transaction updated successfully:', transactionId);

    res.json({
      message: 'Transaction updated successfully',
      transaction: {
        id: updatedTransaction._id,
        type: updatedTransaction.type,
        amount: updatedTransaction.type === 'expense' ? -updatedTransaction.amount : updatedTransaction.amount,
        description: updatedTransaction.description,
        category: updatedTransaction.category,
        date: updatedTransaction.date,
        notes: updatedTransaction.notes,
        updatedAt: updatedTransaction.updatedAt
      }
    });

  } catch (error) {
    console.error('Update transaction error:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message 
    });
  }
});

// Delete transaction endpoint
app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
  try {
    console.log('Delete transaction request:', req.params.id, 'for user:', req.user?.userId);

    const transactionId = req.params.id;

    const deletedTransaction = await Transaction.findOneAndDelete({
      _id: transactionId,
      userId: req.user.userId
    });

    if (!deletedTransaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }

    console.log('Transaction deleted successfully:', transactionId);

    res.json({
      message: 'Transaction deleted successfully',
      deletedId: transactionId
    });

  } catch (error) {
    console.error('Delete transaction error:', error);
    res.status(500).json({ 
      message: 'Server error', 
      error: error.message 
    });
  }
});

// Get transaction statistics endpoint
app.get('/api/transactions/stats', authenticateToken, async (req, res) => {
  try {
    console.log('Get transaction stats for user:', req.user?.userId);

    const { period = 'month' } = req.query; 
    
    const now = new Date();
    let startDate;
    
    switch (period) {
      case 'week':
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 7);
        break;
      case 'year':
        startDate = new Date(now.getFullYear(), 0, 1);
        break;
      case 'month':
      default:
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
    }

    // Aggregate transactions
    const stats = await Transaction.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(req.user.userId),
          date: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$type',
          total: { $sum: '$amount' },
          count: { $sum: 1 },
          categories: {
            $push: {
              category: '$category',
              amount: '$amount'
            }
          }
        }
      }
    ]);

    // Get category breakdown for expenses
    const categoryStats = await Transaction.aggregate([
      {
        $match: {
          userId: new mongoose.Types.ObjectId(req.user.userId),
          type: 'expense',
          date: { $gte: startDate }
        }
      },
      {
        $group: {
          _id: '$category',
          total: { $sum: '$amount' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { total: -1 }
      }
    ]);

    const income = stats.find(s => s._id === 'income') || { total: 0, count: 0 };
    const expenses = stats.find(s => s._id === 'expense') || { total: 0, count: 0 };

    res.json({
      period,
      summary: {
        totalIncome: income.total,
        totalExpenses: expenses.total,
        netAmount: income.total - expenses.total,
        transactionCount: income.count + expenses.count
      },
      categoryBreakdown: categoryStats.map(cat => ({
        category: cat._id,
        amount: cat.total,
        count: cat.count
      })),
      topExpenseCategory: categoryStats[0]?._id || null
    });

  } catch (error) {
    console.error('Get transaction stats error:', error);
    res.status(500).json({ 
      message: 'Error fetching transaction statistics', 
      error: error.message 
    });
  }
});


// Initialize Gemini AI...the pro isn't working..reason why I used the 1.5
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ 
  model: "gemini-1.5-flash",
  generationConfig: {
    temperature: 0.7,
    topK: 40,
    topP: 0.95,
    maxOutputTokens: 1024,
  }
});

const formatCurrency = (amount, currency = 'GHS') => {
  return new Intl.NumberFormat('en-GH', {
    style: 'currency',
    currency: currency,
    minimumFractionDigits: 2
  }).format(Math.abs(amount));
};

// Utility function to analyze transaction patterns
const analyzeTransactions = (transactions) => {
  if (!transactions || transactions.length === 0) {
    return {
      totalSpent: 0,
      totalIncome: 0,
      netAmount: 0,
      categoryBreakdown: {},
      averageExpense: 0,
      topCategories: [],
      spendingTrend: 'No transaction data available',
      transactionCount: 0
    };
  }

  let totalSpent = 0;
  let totalIncome = 0;
  const categoryBreakdown = {};
  
  transactions.forEach(t => {
    const category = t.category || 'Other';
    const amount = Math.abs(t.amount || 0);
    
    if (t.type === 'expense' || t.amount < 0) {
      totalSpent += amount;
      categoryBreakdown[category] = (categoryBreakdown[category] || 0) + amount;
    } else if (t.type === 'income' || t.amount > 0) {
      totalIncome += amount;
    }
  });

  const topCategories = Object.entries(categoryBreakdown)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 3)
    .map(([category, amount]) => ({ category, amount }));

  const netAmount = totalIncome - totalSpent;
  const expenseCount = transactions.filter(t => t.type === 'expense' || t.amount < 0).length;

  return {
    totalSpent,
    totalIncome,
    netAmount,
    categoryBreakdown,
    averageExpense: expenseCount > 0 ? totalSpent / expenseCount : 0,
    topCategories,
    transactionCount: transactions.length,
    spendingTrend: netAmount > 0 ? 'Saving money' : 'Spending more than earning'
  };
};

// Financial Advice Endpoint
app.post('/api/financial-advice', authenticateToken, async (req, res) => {
  try {
    console.log('Financial advice request from user:', req.user?.userId);
    
    const { message, transactions = [], userProfile = {}, context } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ 
        error: 'Message is required',
        success: false 
      });
    }

    if (!process.env.GEMINI_API_KEY) {
      console.error('GEMINI_API_KEY not found in environment variables');
      return res.status(500).json({ 
        error: 'AI service configuration error. Please contact support.',
        success: false 
      });
    }

    const transactionAnalysis = analyzeTransactions(transactions);
    
    // Build comprehensive context for Gemini...still needs somettuinng
    const systemPrompt = `You are an expert financial advisor assistant specifically designed for users in Ghana. You provide personalized, actionable financial advice tailored to the local context.

USER PROFILE:
- Name: ${userProfile.name || 'User'}
- Location: ${userProfile.location || 'Ghana'}
- Currency: ${userProfile.currency || 'GHS'}

CURRENT FINANCIAL SITUATION:
- Total Recent Income: ${formatCurrency(transactionAnalysis.totalIncome, userProfile.currency)}
- Total Recent Expenses: ${formatCurrency(transactionAnalysis.totalSpent, userProfile.currency)}
- Net Amount: ${formatCurrency(transactionAnalysis.netAmount, userProfile.currency)}
- Number of Transactions: ${transactionAnalysis.transactionCount}
- Average Expense: ${formatCurrency(transactionAnalysis.averageExpense, userProfile.currency)}
- Financial Status: ${transactionAnalysis.spendingTrend}
- Top Expense Categories: ${transactionAnalysis.topCategories.map(c => 
  `${c.category} (${formatCurrency(c.amount, userProfile.currency)})`
).join(', ') || 'None'}

GUIDELINES FOR YOUR RESPONSE:
1. **Be Ghana-Specific**: Reference local banks (GCB Bank, Ecobank, Fidelity Bank, Stanbic Bank), mobile money services (MTN Mobile Money, AirtelTigo Money), and investment options (Ghana Treasury Bills, Mutual Funds, Ghana Stock Exchange)
2. **Use Local Context**: Consider Ghana's economic environment, inflation rates, and typical salary ranges in GHS
3. **Be Practical**: Provide actionable steps that can be implemented immediately
4. **Be Encouraging**: Maintain a supportive and motivational tone
5. **Format for Readability**: Use bullet points, clear sections, and highlight key recommendations
6. **Include Specific Numbers**: When suggesting budgets or savings targets, use realistic GHS amounts based on their transaction data
7. **Consider Mobile Banking**: Ghana has high mobile money adoption, so include relevant digital financial services

IMPORTANT DISCLAIMERS:
- Always recommend consulting licensed financial advisors for major investment decisions
- Avoid making guarantees about investment returns
- Focus on practical, implementable advice suitable for Ghana's financial landscape
- Consider the user's actual income and spending patterns from their transaction data

RESPONSE STRUCTURE:
- Start with a brief assessment of their current situation
- Provide 2-3 specific, actionable recommendations
- Include practical next steps they can take this week
- End with encouragement and offer for follow-up questions`;

    // Prepare user message with transaction context
    let userMessage = message.trim();
    
    if (transactions.length > 0) {
      userMessage += `\n\nMy Recent Transactions Context:\n`;
      userMessage += transactions.slice(0, 10).map(t => 
        `- ${t.description}: ${formatCurrency(Math.abs(t.amount), userProfile.currency)} (${t.category}) - ${t.type === 'expense' ? 'Expense' : 'Income'}`
      ).join('\n');
    }

    console.log('Sending request to Gemini AI...');

    // Start chat with Gemini
    const chat = model.startChat({
      history: [
        {
          role: 'user',
          parts: [{ text: systemPrompt }]
        },
        {
          role: 'model', 
          parts: [{ text: 'I understand. I\'m ready to provide personalized financial advice for users in Ghana, taking into account their transaction data, local banking options, and Ghana\'s financial landscape. I\'ll provide practical, actionable advice with specific recommendations tailored to their situation.' }]
        }
      ]
    });

    const result = await chat.sendMessage(userMessage);
    const response = await result.response;
    const advice = response.text();

    console.log(`AI response generated successfully. Length: ${advice.length} characters`);

    return res.status(200).json({
      advice: advice.trim(),
      response: advice.trim(), 
      timestamp: new Date().toISOString(),
      transactionsSummary: transactionAnalysis,
      success: true,
      usage: {
        tokensUsed: 'estimated', 
        model: 'gemini-1.5-flash'
      }
    });

  } catch (error) {
    console.error('Financial advice API error:', error);
    
    let errorMessage = 'I apologize, but I\'m experiencing technical difficulties. Please try again in a moment.';
    let statusCode = 500;

    if (error.message?.toLowerCase().includes('api key') || error.message?.toLowerCase().includes('invalid key')) {
      errorMessage = 'AI service configuration error. Please contact support.';
      statusCode = 500;
    } else if (error.message?.toLowerCase().includes('quota') || error.message?.toLowerCase().includes('limit')) {
      errorMessage = 'AI service is temporarily unavailable due to high demand. Please try again in a few minutes.';
      statusCode = 429;
    } else if (error.message?.toLowerCase().includes('blocked') || error.message?.toLowerCase().includes('safety')) {
      errorMessage = 'I can\'t process that request. Please rephrase your question about financial advice.';
      statusCode = 400;
    } else if (error.message?.toLowerCase().includes('network') || error.message?.toLowerCase().includes('fetch')) {
      errorMessage = 'Unable to connect to AI service. Please check your internet connection and try again.';
      statusCode = 503;
    }

    return res.status(statusCode).json({
      error: errorMessage,
      success: false,
      timestamp: new Date().toISOString(),
      errorType: error.name || 'UnknownError'
    });
  }
});



// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://yoselorm:qipNYQZDujCwHU8x@cluster0.qpvcll7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`CORS enabled for: http://localhost:3000`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;

