import { NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import { hash } from 'bcrypt';
import { supabase } from '@/lib/supabase';

export async function POST(request) {
  try {
    const { email, password, username } = await request.json();

    // Validate input
    if (!email || !password || !username) {
      return NextResponse.json(
        {
          message: 'Email, password, and username are required',
          status: 'Failed'
        },
        { status: 400 }
      );
    }

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .single();

    if (existingUser) {
      return NextResponse.json(
        {
          message: 'User already exists',
          status: 'Failed'
        },
        { status: 422 }
      );
    }

    // Hash password
    const hashedPassword = await hash(password, 10);

    // Create user in Supabase
    const { data: newUser, error: createError } = await supabase
      .from('users')
      .insert([
        {
          email,
          password: hashedPassword,
          username
        }
      ])
      .select()
      .single();

    if (createError) {
      console.error('Error creating user:', createError);
      return NextResponse.json(
        {
          message: 'Failed to create user',
          status: 'Failed'
        },
        { status: 500 }
      );
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: newUser.id,
        email: newUser.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '3d'
      }
    );

    // Create response with user data
    const response = NextResponse.json(
      {
        user: {
          id: newUser.id,
          email: newUser.email,
          username: newUser.username
        },
        token,
        status: 'Success'
      },
      { status: 201 }
    );

    // Set cookie
    response.cookies.set('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 3 * 24 * 60 * 60, 
      path: '/'
    });

    return response;
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      {
        message: 'Internal server error',
        status: 'Failed'
      },
      { status: 500 }
    );
  }
}
