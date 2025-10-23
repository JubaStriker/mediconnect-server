// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import { hashPassword } from '../src/utils/password.utils';

const prisma = new PrismaClient();

async function main() {
    console.log('🌱 Seeding database...');

    // Clear existing data
    await prisma.refreshToken.deleteMany();
    await prisma.emailVerificationToken.deleteMany();
    await prisma.passwordResetToken.deleteMany();
    await prisma.patientProfile.deleteMany();
    await prisma.doctorProfile.deleteMany();
    await prisma.user.deleteMany();

    // Create test patient
    const patientPassword = await hashPassword('Test1234!');
    const patient = await prisma.user.create({
        data: {
            email: 'patient@test.com',
            passwordHash: patientPassword,
            role: 'patient',
            isEmailVerified: true,
            patientProfile: {
                create: {
                    fullName: 'John Doe',
                    phone: '+8801712345678',
                    bloodGroup: 'O+',
                    gender: 'Male',
                    dateOfBirth: new Date('1990-01-15'),
                    address: 'Dhaka, Bangladesh',
                },
            },
        },
    });

    // Create test doctor
    const doctorPassword = await hashPassword('Test1234!');
    const doctor = await prisma.user.create({
        data: {
            email: 'doctor@test.com',
            passwordHash: doctorPassword,
            role: 'doctor',
            isEmailVerified: true,
            doctorProfile: {
                create: {
                    fullName: 'Dr. Jane Smith',
                    specialization: 'Cardiology',
                    licenseNumber: 'BMA-12345',
                    experienceYears: 10,
                    consultationFee: 1500.00,
                    phone: '+8801812345678',
                    bio: 'Experienced cardiologist with 10 years of practice.',
                    isVerified: true,
                },
            },
        },
    });

    // Create more sample doctors
    const specializations = [
        { spec: 'Pediatrics', license: 'BMA-12346' },
        { spec: 'Dermatology', license: 'BMA-12347' },
        { spec: 'Orthopedics', license: 'BMA-12348' },
        { spec: 'Neurology', license: 'BMA-12349' },
    ];

    for (let i = 0; i < specializations.length; i++) {
        const { spec, license } = specializations[i];
        await prisma.user.create({
            data: {
                email: `doctor${i + 2}@test.com`,
                passwordHash: doctorPassword,
                role: 'doctor',
                isEmailVerified: true,
                doctorProfile: {
                    create: {
                        fullName: `Dr. Sample Doctor ${i + 2}`,
                        specialization: spec,
                        licenseNumber: license,
                        experienceYears: 5 + i,
                        consultationFee: 1000 + i * 200,
                        phone: `+88018${1234567 + i}`,
                        isVerified: true,
                    },
                },
            },
        });
    }

    console.log('✅ Seeding complete!');
    console.log('\n📧 Test accounts created:');
    console.log('   Patient: patient@test.com / Test1234!');
    console.log('   Doctor: doctor@test.com / Test1234!');
    console.log('\n🎯 You can now start the server and test authentication!');
}

main()
    .catch((e) => {
        console.error('❌ Seeding failed:', e);
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });