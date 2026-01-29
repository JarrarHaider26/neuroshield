
'use client';

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { User } from "lucide-react";
import React from 'react';

interface UserProfile {
  uid: string;
  name: string;
  email: string;
  role: string;
  joinDate: string;
  avatarUrl?: string | null; 
  bio?: string;
}

interface UserProfileCardProps {
  user: UserProfile;
}

const STATIC_PROFILE_PIC_URL = '/images/rr.png';

export function UserProfileCard({ user }: UserProfileCardProps) {
  const displayAvatarSrc = STATIC_PROFILE_PIC_URL; 

  return (
    <Card className="shadow-xl border-primary/20 overflow-hidden card-hover-effect-primary w-full">
      <CardHeader className="bg-gradient-to-br from-card/50 to-background p-6 border-b border-border">
        <div className="flex flex-col sm:flex-row items-center gap-6">
          <div className="relative group">
            <Avatar className="h-32 w-32 border-4 border-primary shadow-lg">
              <AvatarImage
                src={displayAvatarSrc}
                alt={user.name}
                key={displayAvatarSrc} 
                data-ai-hint="profile picture" 
              />
              <AvatarFallback className="text-4xl bg-primary text-primary-foreground">
                {user.name ? user.name.charAt(0).toUpperCase() : <User />}
              </AvatarFallback>
            </Avatar>
          </div>
          <div className="text-center sm:text-left">
            <CardTitle className="text-3xl font-bold text-primary">{user.name}</CardTitle>
            <CardDescription className="text-lg text-accent">{user.role}</CardDescription>
            <p className="text-sm text-muted-foreground mt-1">Operative since: {user.joinDate}</p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-6 space-y-6">
        <div>
          <Label htmlFor="email" className="text-muted-foreground">Email Address</Label>
          <Input id="email" type="email" value={user.email} readOnly className="mt-1 bg-input/30 border-primary/20 cursor-default" />
        </div>
        <div>
          <Label htmlFor="bio" className="text-muted-foreground">Bio / Mission Statement</Label>
          <Textarea
            id="bio"
            value={user.bio || 'No mission statement provided.'}
            readOnly
            className="mt-1 bg-input/30 border-primary/20 min-h-[100px] cursor-default"
            rows={3}
          />
        </div>
      </CardContent>
      <CardFooter className="p-6 border-t border-border flex flex-col sm:flex-row gap-2 justify-end">
      </CardFooter>
    </Card>
  );
}
